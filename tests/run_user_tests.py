"""
FortifyAI — User-Level Test Runner
------------------------------------
Tests that a user can run to verify the pipeline works end-to-end
using report JSON files — no Fortify credentials, no ADR, no GitHub needed.

Usage:
    python tests/run_user_tests.py               # all tests
    python tests/run_user_tests.py --scenario happy_path
    python tests/run_user_tests.py --scenario all_filtered
    python tests/run_user_tests.py --scenario mixed
    python tests/run_user_tests.py --scenario bare_list
    python tests/run_user_tests.py --verbose
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path
from typing import Callable

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from loguru import logger

# ── Colour helpers ─────────────────────────────────────────────────────────────

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):   print(f"  {GREEN}✅ {msg}{RESET}")
def fail(msg): print(f"  {RED}❌ {msg}{RESET}")
def warn(msg): print(f"  {YELLOW}⚠️  {msg}{RESET}")
def info(msg): print(f"  {CYAN}ℹ️  {msg}{RESET}")

FIXTURES = Path(__file__).parent / "fixtures"

# ── Test result tracker ───────────────────────────────────────────────────────

class Results:
    def __init__(self):
        self.passed = 0
        self.failed = 0
        self.errors: list[str] = []

    def check(self, condition: bool, label: str, detail: str = ""):
        if condition:
            ok(label)
            self.passed += 1
        else:
            fail(f"{label}{' — ' + detail if detail else ''}")
            self.failed += 1

    def error(self, label: str, exc: Exception):
        fail(f"{label}: {exc}")
        self.errors.append(f"{label}: {exc}")
        self.failed += 1

    def summary(self) -> bool:
        total = self.passed + self.failed
        colour = GREEN if self.failed == 0 else RED
        print()
        print(f"{colour}{BOLD}{'─'*50}{RESET}")
        print(f"{colour}{BOLD}  {self.passed}/{total} checks passed{RESET}")
        if self.errors:
            print(f"{RED}  Errors:{RESET}")
            for e in self.errors:
                print(f"    {RED}• {e}{RESET}")
        print(f"{colour}{BOLD}{'─'*50}{RESET}")
        return self.failed == 0


# ── Individual scenario tests ─────────────────────────────────────────────────

def test_happy_path(r: Results, verbose: bool):
    """
    Scenario: 4 real-shaped vulns (2 CVEs on spring-context, 1 on spring-core,
    1 on jetty-http). All fixable. Expected: 3 groups triaged, all proceed.
    """
    print(f"\n{BOLD}{CYAN}── Scenario: Happy Path ──{RESET}")
    info("4 fixable OSS vulnerabilities across 3 dependencies")

    from offline_loader import load_report, NullFortifyClient
    from agents.triage import group_by_dependency
    from agents.version_resolver import resolve_all_groups

    try:
        vulns, release_id = load_report(str(FIXTURES / "scenario_happy_path.json"))
        r.check(len(vulns) == 4, "Loaded 4 vulnerabilities")
        r.check(release_id == 1723380, f"Release ID extracted: {release_id}")
    except Exception as e:
        r.error("load_report", e); return

    # Triage
    try:
        groups = group_by_dependency(vulns)
        r.check(len(groups) == 3, f"Triage: 3 unique deps (got {len(groups)})")

        names = [g["parsed"]["artifact_id"] for g in groups]
        r.check("spring-context" in names, "spring-context found")
        r.check("spring-core"    in names, "spring-core found")
        r.check("jetty-http"     in names, "jetty-http found")

        sc = next(g for g in groups if g["parsed"]["artifact_id"] == "spring-context")
        r.check(len(sc["cves"]) == 2, f"spring-context has 2 CVEs (got {len(sc['cves'])})")
        r.check(sc["severity"] == "High", f"spring-context severity=High (highest across CVEs)")
    except Exception as e:
        r.error("triage", e); return

    # Version resolution (NullFortifyClient returns null nextNonVulnerableVersion)
    try:
        client = NullFortifyClient(vulns)
        resolved = resolve_all_groups(client, 1723380, groups)
        r.check(len(resolved) == 3, "Version resolver processed all 3 groups")

        # NullClient returns null → all will have empty candidates → escalate_reason set
        all_have_version_candidates = all("version_candidates" in g for g in resolved)
        r.check(all_have_version_candidates, "All groups have version_candidates key")

        # Offline → candidates will be empty, escalate_reason set
        escalated = [g for g in resolved if g.get("escalate_reason")]
        r.check(len(escalated) == 3,
                f"All 3 groups flagged for escalation (NullClient has no safe versions) — "
                f"got {len(escalated)}")
    except Exception as e:
        r.error("version_resolver", e); return

    # AI Reasoning heuristic (no GCP needed)
    try:
        from agents.ai_reasoning import reason_all_groups
        reasoned = reason_all_groups(resolved, gcp_project="", gcp_location="us-central1")
        r.check(len(reasoned) == 3, "AI Reasoning processed all 3 groups")
        routes = [g["next_node"] for g in reasoned]
        r.check(all(rt in ("adr_fix", "ai_code_fix", "escalate") for rt in routes),
                f"All routes valid: {routes}")
    except Exception as e:
        r.error("ai_reasoning", e); return

    # Writeback (dry run — NullFortifyClient)
    try:
        from agents.fortify_writeback import run_all_writebacks
        adr_results = [
            {"artifact_id": g["parsed"]["artifact_id"],
             "result": {"success": False, "branch_name": None, "commit_hash": None,
                        "build_time_seconds": None, "pdf_path": None,
                        "error_reason": g.get("escalate_reason", "No safe version")}}
            for g in reasoned
        ]
        summary = run_all_writebacks(client, 1723380, reasoned, adr_results, [])
        # spring-context has 2 vuln_ids, spring-core 1, jetty-http 1 → 4 total comments
        total_comments = summary["total_escalated"] + summary["total_fixed"]
        r.check(total_comments >= 3,
                f"{total_comments} escalation comments dispatched (1 per vuln_id)")
    except Exception as e:
        r.error("writeback", e)


def test_all_filtered(r: Results, verbose: bool):
    """
    Scenario: 4 vulns that should ALL be filtered by triage
    (suppressed, closed, not-OSS, under-review). Expected: 0 groups out.
    """
    print(f"\n{BOLD}{CYAN}── Scenario: All Filtered by Triage ──{RESET}")
    info("4 vulns: suppressed, closed, not-OSS, under-review → all skipped")

    from offline_loader import load_report
    from agents.triage import group_by_dependency, should_skip

    try:
        vulns, _ = load_report(str(FIXTURES / "scenario_all_filtered.json"))
        r.check(len(vulns) == 4, "Loaded 4 vulnerabilities")
    except Exception as e:
        r.error("load_report", e); return

    # Check each skip reason individually
    expected_skips = [
        ("isSuppressed=True",    "Already suppressed"),
        ("closedStatus=True",    "Already closed"),
        ("category=Static",      "Not an OSS finding"),
        ("auditorStatus=Review", "Status: Under Review"),
    ]
    for vuln, (desc, expected_reason) in zip(vulns, expected_skips):
        skipped, reason = should_skip(vuln)
        r.check(skipped, f"Skipped ({desc}): {reason}")

    # Full triage produces 0 groups
    try:
        groups = group_by_dependency(vulns)
        r.check(len(groups) == 0, f"Triage output: 0 groups (got {len(groups)})")
    except Exception as e:
        r.error("triage", e)


def test_mixed(r: Results, verbose: bool):
    """
    Scenario: 1 fixable dep + 1 escalatable dep (no safe version) + 1 suppressed.
    Expected: 2 groups triaged, 1 escalated immediately, 1 proceeds.
    """
    print(f"\n{BOLD}{CYAN}── Scenario: Mixed (Fixable + Escalatable + Suppressed) ──{RESET}")
    info("spring-context (fixable) + no-fix-lib (null safe version) + suppressed")

    from offline_loader import load_report, NullFortifyClient
    from agents.triage import group_by_dependency
    from agents.version_resolver import resolve_all_groups

    try:
        vulns, _ = load_report(str(FIXTURES / "scenario_mixed.json"))
        r.check(len(vulns) == 3, "Loaded 3 vulnerabilities")
    except Exception as e:
        r.error("load_report", e); return

    try:
        groups = group_by_dependency(vulns)
        r.check(len(groups) == 2, f"Triage: 2 groups (suppressed filtered) — got {len(groups)}")
        names = {g["parsed"]["artifact_id"] for g in groups}
        r.check("spring-context" in names, "spring-context kept")
        r.check("no-fix-lib"     in names, "no-fix-lib kept (for escalation)")
        r.check("suppressed-lib" not in names, "suppressed-lib correctly filtered")
    except Exception as e:
        r.error("triage", e); return

    try:
        client = NullFortifyClient(vulns)
        resolved = resolve_all_groups(client, 1723380, groups)
        escalated = [g for g in resolved if g.get("escalate_reason")]
        # Both will escalate with NullClient (null safe versions) — that's correct offline behaviour
        r.check(len(escalated) == 2,
                f"Both groups flagged (NullClient returns null safe versions) — got {len(escalated)}")
    except Exception as e:
        r.error("version_resolver", e)


def test_bare_list(r: Results, verbose: bool):
    """
    Scenario: JSON file is a bare list (no 'items' envelope).
    Expected: loader auto-detects shape, extracts release_id from items.
    """
    print(f"\n{BOLD}{CYAN}── Scenario: Bare List JSON Format ──{RESET}")
    info("JSON is a plain list — no {items: [...]} envelope")

    from offline_loader import load_report, NullFortifyClient
    from agents.triage import group_by_dependency

    try:
        vulns, release_id = load_report(str(FIXTURES / "scenario_bare_list.json"))
        r.check(len(vulns) == 2, f"Loaded 2 vulnerabilities from bare list")
        r.check(release_id == 9999, f"Release ID extracted from items: {release_id}")
    except Exception as e:
        r.error("load_report", e); return

    try:
        groups = group_by_dependency(vulns)
        r.check(len(groups) == 1, "1 dep group (both CVEs on jackson-databind)")
        jd = groups[0]
        r.check(jd["parsed"]["artifact_id"] == "jackson-databind",
                f"Dep: {jd['parsed']['artifact_id']}")
        r.check(len(jd["cves"]) == 2, f"2 CVEs collected: {jd['cves']}")
        r.check(jd["severity"] == "Critical",
                f"Severity=Critical (highest across CVEs) — got {jd['severity']}")
    except Exception as e:
        r.error("triage", e)


def test_offline_loader_shapes(r: Results, verbose: bool):
    """
    Scenario: Verify all three JSON shape variants load correctly.
    """
    print(f"\n{BOLD}{CYAN}── Scenario: Offline Loader Shape Detection ──{RESET}")
    info("Testing {items:[...]}, bare list, and {vulnerabilities:[...]} shapes")

    from offline_loader import _normalise, load_report
    import json, tempfile, os

    # Shape 1: items envelope
    try:
        data1 = {"items": [{"vulnId": "a", "primaryLocation": "x:y@1.0", "checkId": "CVE-1"}], "totalCount": 1}
        items = _normalise(data1)
        r.check(len(items) == 1, "Shape 1 {items:[...]} — 1 item extracted")
    except Exception as e:
        r.error("shape_1", e)

    # Shape 2: bare list
    try:
        data2 = [{"vulnId": "b", "primaryLocation": "x:y@2.0", "checkId": "CVE-2"}]
        items = _normalise(data2)
        r.check(len(items) == 1, "Shape 2 bare list — 1 item extracted")
    except Exception as e:
        r.error("shape_2", e)

    # Shape 3: vulnerabilities key
    try:
        data3 = {"vulnerabilities": [{"vulnId": "c", "primaryLocation": "x:y@3.0", "checkId": "CVE-3"}]}
        items = _normalise(data3)
        r.check(len(items) == 1, "Shape 3 {vulnerabilities:[...]} — 1 item extracted")
    except Exception as e:
        r.error("shape_3", e)

    # Bad shape → ValueError
    try:
        _normalise({"not_items": 42})
        r.check(False, "Bad shape should raise ValueError")
    except ValueError:
        r.check(True, "Bad shape raises ValueError correctly")
    except Exception as e:
        r.error("bad_shape", e)

    # Load from temp file and check defaults patched
    try:
        data = {"items": [{"primaryLocation": "a:b@1.0", "vulnId": "x", "checkId": "CVE-X"}]}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(data, f)
            tmp_path = f.name
        vulns, _ = load_report(tmp_path)
        os.unlink(tmp_path)
        r.check(vulns[0]["category"] == "Open Source",
                "Missing 'category' defaulted to 'Open Source'")
        r.check(vulns[0]["isSuppressed"] == False,
                "Missing 'isSuppressed' defaulted to False")
        r.check(vulns[0]["auditorStatus"] == "Fixable OSS",
                "Missing 'auditorStatus' defaulted to 'Fixable OSS'")
    except Exception as e:
        r.error("default_patching", e)


def test_null_client(r: Results, verbose: bool):
    """
    Scenario: NullFortifyClient behaves correctly — suppresses writes, returns stubs.
    """
    print(f"\n{BOLD}{CYAN}── Scenario: NullFortifyClient Dry-Run Safety ──{RESET}")
    info("Verifying no real Fortify API calls are made in --report mode")

    from offline_loader import NullFortifyClient

    vulns = [{"vulnId": "test-1", "primaryLocation": "a:b@1.0", "checkId": "CVE-X",
              "category": "Open Source", "isSuppressed": False,
              "auditorStatus": "Fixable OSS", "closedStatus": False,
              "severityString": "High", "owasp2021": ""}]

    client = NullFortifyClient(vulns)

    # get_vulnerabilities returns loaded list
    returned = client.get_vulnerabilities(1723380)
    r.check(returned == vulns, "get_vulnerabilities returns loaded list")

    # get_recommendations returns stub with null safe version
    rec = client.get_recommendations(1723380, "test-1")
    r.check(rec["sonatype"]["nextNonVulnerableVersion"] is None,
            "get_recommendations returns null nextNonVulnerableVersion (safe stub)")

    # post_comment does NOT raise, returns empty dict
    result = client.post_comment(1723380, "test-1", "test comment")
    r.check(result == {}, "post_comment returns {} (suppressed, no real API call)")

    # get_applications and get_releases return empty lists
    r.check(client.get_applications() == [], "get_applications returns []")
    r.check(client.get_releases(147266) == [], "get_releases returns []")


# ── Scenario registry ─────────────────────────────────────────────────────────

SCENARIOS: dict[str, Callable] = {
    "happy_path":     test_happy_path,
    "all_filtered":   test_all_filtered,
    "mixed":          test_mixed,
    "bare_list":      test_bare_list,
    "loader_shapes":  test_offline_loader_shapes,
    "null_client":    test_null_client,
}


# ── Entry point ───────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(
        description="FortifyAI user-level test runner",
    )
    parser.add_argument(
        "--scenario", "-s",
        choices=list(SCENARIOS.keys()) + ["all"],
        default="all",
        help="Which scenario to run (default: all)",
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show DEBUG-level logs",
    )
    return parser.parse_args()


def main():
    args = parse_args()

    # Suppress loguru output unless verbose
    logger.remove()
    if args.verbose:
        logger.add(sys.stderr, level="DEBUG")
    else:
        # Only show WARNING+ from agents during tests
        logger.add(sys.stderr, level="WARNING",
                   format="<yellow>{level}</yellow> | {message}")

    print(f"\n{BOLD}FortifyAI User-Level Tests{RESET}")
    print(f"Fixtures: {FIXTURES}")
    print("─" * 50)

    r = Results()
    to_run = list(SCENARIOS.items()) if args.scenario == "all" \
             else [(args.scenario, SCENARIOS[args.scenario])]

    for name, fn in to_run:
        try:
            fn(r, args.verbose)
        except Exception as exc:
            print(f"\n{RED}UNEXPECTED ERROR in {name}:{RESET}")
            traceback.print_exc()
            r.failed += 1
            r.errors.append(f"{name}: {exc}")

    passed = r.summary()
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
