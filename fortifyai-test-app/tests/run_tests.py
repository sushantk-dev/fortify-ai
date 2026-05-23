"""
FortifyAI — Full Project Test Runner
======================================
Tests all 8 scenarios using the fortify_report_all_scenarios.json report.
Run from the fortify-ai directory:

    python fortifyai-test-app/tests/run_tests.py
    python fortifyai-test-app/tests/run_tests.py --verbose
    python fortifyai-test-app/tests/run_tests.py --scenario SC-01
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Callable

# Add fortify-ai to path
FORTIFYAI_ROOT = Path(__file__).parent.parent.parent / "fortify-ai"
if not FORTIFYAI_ROOT.exists():
    # try sibling directory
    FORTIFYAI_ROOT = Path(__file__).parent.parent.parent / "fortifyai"
if not FORTIFYAI_ROOT.exists():
    FORTIFYAI_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(FORTIFYAI_ROOT))

PROJECT_ROOT  = Path(__file__).parent.parent
REPORT_FILE   = PROJECT_ROOT / "tests" / "fortify_report_all_scenarios.json"

# ── Colour helpers ─────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"    {GREEN}✅ {msg}{RESET}")
def fail(msg): print(f"    {RED}❌ {msg}{RESET}")
def info(msg): print(f"    {CYAN}ℹ️  {msg}{RESET}")
def warn(msg): print(f"    {YELLOW}⚠️  {msg}{RESET}")
def header(sc, title):
    print(f"\n{BOLD}{CYAN}{'─'*55}{RESET}")
    print(f"{BOLD}{CYAN}  {sc}: {title}{RESET}")
    print(f"{BOLD}{CYAN}{'─'*55}{RESET}")


class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, condition: bool, label: str, detail: str = ""):
        if condition:
            ok(label)
            self.passed += 1
        else:
            fail(f"{label}{' — ' + detail if detail else ''}")
            self.failed += 1

    def summary(self) -> bool:
        total = self.passed + self.failed
        colour = GREEN if self.failed == 0 else RED
        print(f"\n{colour}{BOLD}{'═'*55}{RESET}")
        print(f"{colour}{BOLD}  Result: {self.passed}/{total} checks passed{RESET}")
        print(f"{colour}{BOLD}{'═'*55}{RESET}")
        return self.failed == 0


# ── Shared fixture ─────────────────────────────────────────────────────────────

def load_all(r: Results):
    """Load and validate the master report. Returns (vulns, release_id)."""
    from offline_loader import load_report
    try:
        vulns, release_id = load_report(str(REPORT_FILE))
        r.check(len(vulns) == 11, f"Loaded 11 items from master report (got {len(vulns)})")
        r.check(release_id == 9990001, f"Release ID = 9990001 (got {release_id})")
        return vulns, release_id
    except Exception as e:
        fail(f"Failed to load report: {e}")
        r.failed += 1
        return [], 0


# ── SC-01: Happy Path ──────────────────────────────────────────────────────────

def test_sc01(r: Results, verbose: bool):
    header("SC-01", "Happy Path — all fixable, no breaking changes")
    info("6 fixable OSS vulns across 5 deps (after dedup)")
    info("jackson 2.9.8, log4j 2.14.1, jetty 12.0.0 → all patch upgrades")

    vulns, release_id = load_all(r)
    if not vulns: return

    from agents.triage import group_by_dependency
    from offline_loader import NullFortifyClient
    from agents.version_resolver import resolve_all_groups
    from agents.ai_reasoning import _heuristic_reasoning, route_from_reasoning
    from state import ApiDiffResult

    # Triage — expect 5 unique deps (SC-07 items get filtered below)
    oss_fixable = [v for v in vulns
                   if not v["isSuppressed"] and not v["closedStatus"]
                   and v["category"] == "Open Source"
                   and v["auditorStatus"] == "Fixable OSS"]
    groups = group_by_dependency(oss_fixable)

    expected_deps = {"spring-context", "spring-core", "jetty-http",
                     "jackson-databind", "log4j-core", "no-fix-available"}
    found_deps = {g["parsed"]["artifact_id"] for g in groups}
    r.check(expected_deps == found_deps,
            f"All expected deps found: {sorted(found_deps)}")

    # Happy path deps: patch upgrades → no breaking changes → high confidence → adr_fix
    for dep_name in ["jetty-http", "jackson-databind", "log4j-core"]:
        g = next((x for x in groups if x["parsed"]["artifact_id"] == dep_name), None)
        if not g: continue
        g["api_diff"] = ApiDiffResult(
            has_breaking_changes=False, breaking_count=0,
            affected_lines=[], raw_output="No changes detected."
        )
        g["version_candidates"] = {"candidates": ["safe-version"], "explanation": ""}
        result = _heuristic_reasoning(g, "safe-version")
        route  = route_from_reasoning(result)
        r.check(result["confidence"] == "high",
                f"{dep_name}: confidence=high (patch upgrade)")
        r.check(result["pre_fix_required"] == False,
                f"{dep_name}: pre_fix_required=False")
        r.check(route == "adr_fix",
                f"{dep_name}: routes to adr_fix directly")


# ── SC-02: Breaking Change ─────────────────────────────────────────────────────

def test_sc02(r: Results, verbose: bool):
    header("SC-02", "Breaking Change — setDisallowedFields() removed in spring 6.x")
    info("spring-context 5.3.31 → 6.1.20")
    info("DataBinderController.java:35 and :37 call removed API methods")

    from agents.triage import group_by_dependency
    from agents.ai_reasoning import _heuristic_reasoning, route_from_reasoning
    from state import ApiDiffResult

    vulns, _ = load_all(r)
    if not vulns: return

    groups = group_by_dependency(vulns)
    sc = next((g for g in groups if g["parsed"]["artifact_id"] == "spring-context"), None)
    r.check(sc is not None, "spring-context group found")
    if not sc: return

    # Simulate japicmp detecting 2 removed methods
    sc["api_diff"] = ApiDiffResult(
        has_breaking_changes=True,
        breaking_count=2,
        affected_lines=[
            "DataBinderController.java:35",   # setDisallowedFields
            "DataBinderController.java:37",   # isAllowed
        ],
        raw_output=(
            "!!! BINARY INCOMPATIBLE CHANGE: REMOVED METHOD: "
            "public void org.springframework.web.bind.WebDataBinder.setDisallowedFields(String[])\n"
            "!!! BINARY INCOMPATIBLE CHANGE: REMOVED METHOD: "
            "public boolean org.springframework.web.bind.WebDataBinder.isAllowed(String)"
        ),
    )
    sc["version_candidates"] = {"candidates": ["6.1.20", "7.0.7"], "explanation": "DataBinder API changed"}
    sc["calling_files"] = [
        "api/src/main/java/com/example/api/controller/DataBinderController.java"
    ]

    result = _heuristic_reasoning(sc, "6.1.20")
    route  = route_from_reasoning(result)

    r.check(result["safe"] == True,       "safe=True (fixable with code change)")
    r.check(result["confidence"] == "medium", f"confidence=medium (got {result['confidence']})")
    r.check(result["pre_fix_required"] == True, "pre_fix_required=True")
    r.check(len(result["at_risk_lines"]) == 2,
            f"2 at-risk lines (got {result['at_risk_lines']})")
    r.check("DataBinderController.java:35" in result["at_risk_lines"],
            "DataBinderController.java:35 flagged")
    r.check("DataBinderController.java:37" in result["at_risk_lines"],
            "DataBinderController.java:37 flagged")
    r.check(route == "ai_code_fix",
            f"routes to ai_code_fix (got '{route}')")

    print(f"\n    {CYAN}Routing:{RESET} Breaking change → {YELLOW}ai_code_fix{RESET} → adr_fix → PR")


# ── SC-03: Multiple CVEs same dep ─────────────────────────────────────────────

def test_sc03(r: Results, verbose: bool):
    header("SC-03", "Multiple CVEs — spring-context has CVE-2024-38820 (High) + CVE-2025-22233 (Low)")
    info("Severity must be High (highest across both CVEs, not Low)")
    info("Both CVE IDs must be in the cves[] list after grouping")

    vulns, _ = load_all(r)
    if not vulns: return

    from agents.triage import group_by_dependency
    groups = group_by_dependency(vulns)
    sc = next((g for g in groups if g["parsed"]["artifact_id"] == "spring-context"), None)
    r.check(sc is not None, "spring-context group found")
    if not sc: return

    r.check(len(sc["cves"]) == 2,
            f"2 CVEs collected for spring-context (got {sc['cves']})")
    r.check("CVE-2024-38820" in sc["cves"], "CVE-2024-38820 present")
    r.check("CVE-2025-22233" in sc["cves"], "CVE-2025-22233 present")
    r.check(sc["severity"] == "High",
            f"Severity=High (highest of High+Low) — got {sc['severity']}")
    r.check(len(sc["vuln_ids"]) == 2,
            f"2 vuln_ids collected (got {sc['vuln_ids']})")

    info("spring-context will be fixed ONCE and both CVEs resolved together")


# ── SC-04: Property-referenced version ────────────────────────────────────────

def test_sc04(r: Results, verbose: bool):
    header("SC-04", "Property-Referenced Version — ${spring.version} in root pom.xml")
    info("FortifyAI context agent must detect version_property=${spring.version}")
    info("ADR fix type: update the property value, not the <version> tag")

    from agents.context import locate_dependency, _find_dep_in_pom
    from pathlib import Path

    r.check(PROJECT_ROOT.exists(), f"Project root exists: {PROJECT_ROOT}")

    # Test: api/pom.xml should have spring-context with ${spring.version}
    api_pom = PROJECT_ROOT / "api" / "pom.xml"
    r.check(api_pom.exists(), f"api/pom.xml exists: {api_pom}")

    if api_pom.exists():
        match = _find_dep_in_pom(api_pom, "org.springframework", "spring-context")
        r.check(match is not None, "spring-context found in api/pom.xml")
        if match:
            r.check(match["version_property"] is not None,
                    f"version_property detected: {match['version_property']}")
            r.check("spring.version" in (match["version_property"] or ""),
                    f"version_property=${match.get('version_property')}")

    # Test: jackson-databind in api/pom.xml should be hardcoded (no property)
    if api_pom.exists():
        jmatch = _find_dep_in_pom(api_pom, "com.fasterxml.jackson.core", "jackson-databind")
        r.check(jmatch is not None, "jackson-databind found in api/pom.xml")
        if jmatch:
            r.check(jmatch["version_property"] is None,
                    f"jackson-databind is hardcoded (no property) — got {jmatch.get('version_property')}")
            r.check(jmatch.get("version_raw") == "2.9.8",
                    f"Hardcoded version=2.9.8 — got {jmatch.get('version_raw')}")


# ── SC-05: Hardcoded version ───────────────────────────────────────────────────

def test_sc05(r: Results, verbose: bool):
    header("SC-05", "Hardcoded Version — jackson-databind <version>2.9.8</version> in api/pom.xml")
    info("ADR fix type: update the <version> tag directly in api/pom.xml")
    info("Contrast with SC-04 where ADR updates a ${property} instead")

    from agents.context import _find_dep_in_pom
    api_pom = PROJECT_ROOT / "api" / "pom.xml"

    r.check(api_pom.exists(), "api/pom.xml exists")
    if not api_pom.exists(): return

    match = _find_dep_in_pom(api_pom, "com.fasterxml.jackson.core", "jackson-databind")
    r.check(match is not None, "jackson-databind found in api/pom.xml")
    if not match: return

    r.check(match["version_property"] is None,
            "No property reference (hardcoded)")
    r.check(match.get("version_raw") == "2.9.8",
            f"Hardcoded 2.9.8 confirmed — got {match.get('version_raw')}")
    r.check(match.get("resolved_version") == "2.9.8",
            f"Resolved version = 2.9.8 — got {match.get('resolved_version')}")
    r.check(match.get("is_direct", True) == True,
            "is_direct = True")

    print(f"\n    {CYAN}ADR fix strategy:{RESET} updates <version>2.9.8</version> tag inline in api/pom.xml")


# ── SC-06: Transitive dependency ───────────────────────────────────────────────

def test_sc06(r: Results, verbose: bool):
    header("SC-06", "Transitive Dependency — spring-core not declared in any pom directly")
    info("spring-core is pulled in by spring-context (transitive)")
    info("FortifyAI context agent must detect is_direct=False")
    info("ADR fix type: pin via <dependencyManagement> in root pom.xml")

    from agents.context import _find_dep_in_pom
    from pathlib import Path

    all_poms = list(PROJECT_ROOT.rglob("pom.xml"))
    r.check(len(all_poms) >= 4, f"Found {len(all_poms)} pom.xml files")

    # spring-core should NOT be found as a direct dep in any pom
    found_direct = False
    for pom in all_poms:
        match = _find_dep_in_pom(pom, "org.springframework", "spring-core")
        if match:
            # dependencyManagement declarations don't count as direct deps
            rel = str(pom.relative_to(PROJECT_ROOT))
            if "pom.xml" == rel:  # root pom — only in dependencyManagement
                continue
            found_direct = True
            info(f"Found spring-core in {rel} — checking if it's a management entry")

    r.check(not found_direct,
            "spring-core NOT declared as direct dep in any module pom")

    # Triage still picks it up from the Fortify report
    vulns, _ = load_all(r)
    from agents.triage import group_by_dependency
    groups = group_by_dependency(vulns)
    sk = next((g for g in groups if g["parsed"]["artifact_id"] == "spring-core"), None)
    r.check(sk is not None, "spring-core group present (from Fortify report)")

    print(f"\n    {CYAN}ADR fix strategy:{RESET} injects <dependencyManagement> pin in root pom.xml")


# ── SC-07: Triage filtering ────────────────────────────────────────────────────

def test_sc07(r: Results, verbose: bool):
    header("SC-07", "Triage Filtering — 4 findings must be skipped")
    info("suppressed=true / closedStatus=true / category=Static Analysis / auditorStatus=Under Review")

    vulns, _ = load_all(r)
    if not vulns: return

    from agents.triage import should_skip, group_by_dependency

    # Find the 4 filtered items by their primaryLocation
    filter_cases = [
        ("com.example:legacy-suppressed@1.0.0",  "isSuppressed=true",    "Already suppressed"),
        ("com.example:already-closed@2.0.0",      "closedStatus=true",    "Already closed"),
        ("com.example:static-finding@3.0.0",      "category=Static",      "Not an OSS finding"),
        ("com.example:under-review@4.0.0",         "auditorStatus=Review", "Status: Under Review"),
    ]

    for loc, desc, expected_prefix in filter_cases:
        vuln = next((v for v in vulns if v.get("primaryLocation") == loc), None)
        r.check(vuln is not None, f"Found test vuln for {desc}")
        if not vuln: continue

        skipped, reason = should_skip(vuln)
        r.check(skipped == True, f"SKIP: {desc} — reason: {reason}")
        r.check(expected_prefix.split(":")[0].lower() in reason.lower() or
                any(w in reason for w in expected_prefix.replace("=", " ").split()),
                f"Reason contains expected text '{expected_prefix}': '{reason}'")

    # Full triage output should have 0 of these 4 deps
    groups = group_by_dependency(vulns)
    filtered_names = {"legacy-suppressed", "already-closed",
                      "static-finding", "under-review"}
    found_filtered = {g["parsed"]["artifact_id"] for g in groups} & filtered_names
    r.check(len(found_filtered) == 0,
            f"None of the 4 filtered deps appear in triage output (found: {found_filtered})")

    # Correct count of passing groups
    passing = [g for g in groups if g["parsed"]["artifact_id"] not in filtered_names]
    r.check(len(passing) == len(groups),
            f"{len(groups)} valid groups proceed to next stage")


# ── SC-08: Escalation (no safe version) ───────────────────────────────────────

def test_sc08(r: Results, verbose: bool):
    header("SC-08", "Escalation — no-fix-available has null nextNonVulnerableVersion")
    info("NullFortifyClient returns null for all recommendations")
    info("version_resolver must set escalate_reason and empty candidates list")
    info("Fortify writeback must post escalation comment (dry-run in --report mode)")

    vulns, release_id = load_all(r)
    if not vulns: return

    from agents.triage import group_by_dependency
    from agents.version_resolver import resolve_all_groups
    from offline_loader import NullFortifyClient
    from agents.fortify_writeback import _escalated_comment

    groups = group_by_dependency(vulns)
    nf = next((g for g in groups if g["parsed"]["artifact_id"] == "no-fix-available"), None)
    r.check(nf is not None, "no-fix-available group in triage output")
    if not nf: return

    # Version resolver with NullClient → null safe version → escalate_reason set
    client = NullFortifyClient(vulns)
    resolved = resolve_all_groups(client, release_id, [nf])
    r.check(len(resolved) == 1, "1 group resolved")

    resolved_nf = resolved[0]
    r.check(resolved_nf.get("escalate_reason") is not None,
            f"escalate_reason set: {resolved_nf.get('escalate_reason', '')[:60]}...")
    r.check(len(resolved_nf.get("version_candidates", {}).get("candidates", [])) == 0,
            "candidates list is empty (no safe version)")

    # Escalation comment content
    comment = _escalated_comment(resolved_nf, resolved_nf.get("escalate_reason"))
    r.check("[FortifyAI] Escalated" in comment,       "Comment header present")
    r.check("no-fix-available" in comment,            "Dep name in comment")
    r.check("CVE-9999-9999" in comment,               "CVE ID in comment")
    r.check("Next steps:" in comment,                 "Next steps section present")
    r.check("(none)" in comment,                      "Tried: (none) shown")

    # post_comment suppressed in dry-run
    result = client.post_comment(release_id, "escalation-vuln-uuid-001", comment)
    r.check(result == {},  "post_comment suppressed → {} returned (no Fortify API call)")

    print(f"\n    {CYAN}Escalation path:{RESET}")
    print(f"      null nextNonVulnerableVersion → escalate_reason set → writeback: escalation comment")


# ── Scenario registry ──────────────────────────────────────────────────────────

SCENARIOS: dict[str, Callable] = {
    "SC-01": test_sc01,
    "SC-02": test_sc02,
    "SC-03": test_sc03,
    "SC-04": test_sc04,
    "SC-05": test_sc05,
    "SC-06": test_sc06,
    "SC-07": test_sc07,
    "SC-08": test_sc08,
}


# ── Entry point ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="FortifyAI — Full Project Test Runner",
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="all",
        help="Which scenario to run (default: all)",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    return parser.parse_args()


def main():
    args = parse_args()

    try:
        from loguru import logger
        logger.remove()
        if args.verbose:
            logger.add(sys.stderr, level="DEBUG")
        else:
            logger.add(sys.stderr, level="WARNING",
                       format="<yellow>{level}</yellow> | {message}")
    except ImportError:
        pass

    print(f"\n{BOLD}FortifyAI — Full Project Test Runner{RESET}")
    print(f"Project : {PROJECT_ROOT}")
    print(f"Report  : {REPORT_FILE}")
    print("═" * 55)

    r = Results()
    to_run = list(SCENARIOS.items()) if args.scenario == "all" \
             else [(args.scenario, SCENARIOS[args.scenario])]

    for name, fn in to_run:
        try:
            fn(r, args.verbose)
        except Exception as exc:
            fail(f"UNEXPECTED ERROR in {name}: {exc}")
            if args.verbose:
                traceback.print_exc()
            r.failed += 1

    r.summary()
    sys.exit(0 if r.failed == 0 else 1)


if __name__ == "__main__":
    main()
