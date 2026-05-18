"""
FortifyAI — Fortify Writeback Agent (Iteration 11)
----------------------------------------------------
Responsibility:
  After the pipeline completes (either fixed or escalated), write a comment
  back to every Fortify vulnerability that was processed.

  Fixed vulns — one comment per vuln_id in the group:
    [FortifyAI] Auto-remediated
    Fix:    org.springframework:spring-context 5.3.31 → 6.1.20
    Build:  PASSED (87s)
    Branch: feature/FORTIFY-a4105c54_fix_20260517
    Commit: 3f8a21bc
    PR:     https://github.com/acme/backend/pull/482
    CVEs:   CVE-2024-38820, CVE-2025-22233

  Escalated vulns — explanation of what was tried and what to do next:
    [FortifyAI] Escalated — manual action required
    Dependency: org.springframework:spring-context 5.3.31
    Reason:     No safe version available from Fortify recommendations
    Tried:      (none — null nextNonVulnerableVersion)
    Next steps: Contact the dependency maintainer or apply a mitigating control

Console output (done-when):
  [Writeback] ✅ Comment posted to vuln a4105c54 (CVE-2024-38820)
  [Writeback] ✅ Comment posted to vuln 39a7c4f2 (CVE-2025-22233)
  [Writeback] ✅ All writebacks complete
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from loguru import logger

from fortify_client import FortifyClient
from state import AgentState


# ── Comment builders ──────────────────────────────────────────────────────────

def _fixed_comment(
    group: dict,
    adr_result: dict,
    pr_result: dict,
) -> str:
    """Build the fix-outcome comment for a successfully remediated dependency."""
    parsed       = group["parsed"]
    group_id     = parsed["group_id"]
    artifact_id  = parsed["artifact_id"]
    current_ver  = parsed["current_version"]
    candidate    = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )
    cves         = group.get("cves", [])
    branch       = adr_result.get("branch_name", "unknown")
    commit       = adr_result.get("commit_hash", "unknown")
    build_time   = adr_result.get("build_time_seconds")
    pr_url       = pr_result.get("pr_url", "")

    build_str    = f"PASSED ({build_time}s)" if build_time else "PASSED"
    cve_str      = ", ".join(cves)
    dep_str      = f"{group_id}:{artifact_id}"
    ts           = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "[FortifyAI] Auto-remediated",
        f"Fix:        {dep_str} {current_ver} → {candidate}",
        f"Build:      {build_str}",
        f"Branch:     {branch}",
        f"Commit:     {commit}",
    ]
    if pr_url:
        lines.append(f"PR:         {pr_url}")
    lines.append(f"CVEs:       {cve_str}")
    lines.append(f"Timestamp:  {ts}")

    return "\n".join(lines)


def _escalated_comment(
    group: dict,
    escalation_reason: Optional[str],
) -> str:
    """Build the escalation comment for a dep that could not be auto-fixed."""
    parsed       = group["parsed"]
    group_id     = parsed["group_id"]
    artifact_id  = parsed["artifact_id"]
    current_ver  = parsed["current_version"]
    cves         = group.get("cves", [])
    candidates   = group.get("version_candidates", {}).get("candidates", [])
    tried_str    = ", ".join(candidates) if candidates else "(none)"
    reason       = (
        escalation_reason
        or group.get("escalate_reason")
        or "Max retries exceeded with no successful build"
    )
    dep_str      = f"{group_id}:{artifact_id}"
    ts           = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "[FortifyAI] Escalated — manual action required",
        f"Dependency: {dep_str} {current_ver}",
        f"CVEs:       {', '.join(cves) or '(see finding)'}",
        f"Reason:     {reason}",
        f"Tried:      {tried_str}",
        "",
        "Next steps:",
        "  1. Review the Sonatype recommendation for this finding",
        "  2. Check whether a patched version exists on Maven Central",
        "  3. Consider a mitigating control if no safe version is available",
        "  4. Contact the dependency maintainer if the CVE is unpatched",
        f"Timestamp:  {ts}",
    ]

    return "\n".join(lines)


# ── Writeback executor ────────────────────────────────────────────────────────

def post_fixed_comments(
    client: FortifyClient,
    release_id: int,
    group: dict,
    adr_result: dict,
    pr_result: dict,
) -> int:
    """
    Post a fix-outcome comment to every vuln_id in the group.
    Returns the count of successful posts.
    """
    vuln_ids: list[str] = group.get("vuln_ids", [])
    if not vuln_ids:
        rep = group.get("representative_vuln_id")
        if rep:
            vuln_ids = [rep]

    comment = _fixed_comment(group, adr_result, pr_result)
    cves     = group.get("cves", [])
    posted   = 0

    for i, vuln_id in enumerate(vuln_ids):
        cve_label = cves[i] if i < len(cves) else vuln_id[:8]
        try:
            client.post_comment(release_id, vuln_id, comment)
            logger.info(
                f"[Writeback] ✅ Comment posted to vuln {vuln_id[:8]} ({cve_label})"
            )
            posted += 1
        except Exception as exc:
            logger.warning(
                f"[Writeback] ❌ Failed to post to vuln {vuln_id[:8]}: {exc}"
            )

    return posted


def post_escalated_comments(
    client: FortifyClient,
    release_id: int,
    group: dict,
    escalation_reason: Optional[str],
) -> int:
    """
    Post an escalation comment to every vuln_id in the group.
    Returns the count of successful posts.
    """
    vuln_ids: list[str] = group.get("vuln_ids", [])
    if not vuln_ids:
        rep = group.get("representative_vuln_id")
        if rep:
            vuln_ids = [rep]

    comment  = _escalated_comment(group, escalation_reason)
    cves     = group.get("cves", [])
    posted   = 0

    for i, vuln_id in enumerate(vuln_ids):
        cve_label = cves[i] if i < len(cves) else vuln_id[:8]
        try:
            client.post_comment(release_id, vuln_id, comment)
            logger.info(
                f"[Writeback] ✅ Escalation comment posted to vuln {vuln_id[:8]} ({cve_label})"
            )
            posted += 1
        except Exception as exc:
            logger.warning(
                f"[Writeback] ❌ Failed to escalation-comment vuln {vuln_id[:8]}: {exc}"
            )

    return posted


def run_all_writebacks(
    client: FortifyClient,
    release_id: int,
    groups: list[dict],
    adr_results: list[dict],
    pr_results: list[dict],
    escalation_reason: Optional[str] = None,
) -> dict:
    """
    Dispatch fix or escalation comments for all groups.

    adr_results: [{"artifact_id": ..., "result": AdrResult}]
    pr_results:  [PrResult, ...]  (in same order as groups that have a PR)

    Returns summary dict with total_fixed, total_escalated, total_failed.
    """
    # Build lookups by artifact_id
    adr_by_artifact = {
        r["artifact_id"]: r["result"]
        for r in adr_results
    }
    # Map artifact_id → pr_result (pr_results are in order of groups that had ADR success)
    pr_by_artifact: dict[str, dict] = {}
    pr_idx = 0
    for g in groups:
        art = g["parsed"]["artifact_id"]
        adr = adr_by_artifact.get(art, {})
        if adr.get("success") and pr_idx < len(pr_results):
            pr_by_artifact[art] = pr_results[pr_idx]
            pr_idx += 1

    total_fixed     = 0
    total_escalated = 0
    total_failed    = 0

    for group in groups:
        art        = group["parsed"]["artifact_id"]
        adr_result = adr_by_artifact.get(art, {})
        pr_result  = pr_by_artifact.get(art, {})

        if adr_result.get("success"):
            n = post_fixed_comments(client, release_id, group, adr_result, pr_result)
            if n > 0:
                total_fixed += n
            else:
                total_failed += len(group.get("vuln_ids", [1]))
        else:
            # Build failed or escalated — post escalation comment
            reason = (
                group.get("escalate_reason")
                or escalation_reason
                or adr_result.get("error_reason")
                or "Automated fix was not possible"
            )
            n = post_escalated_comments(client, release_id, group, reason)
            if n > 0:
                total_escalated += n
            else:
                total_failed += len(group.get("vuln_ids", [1]))

    logger.info(
        f"[Writeback] ✅ All writebacks complete — "
        f"fixed={total_fixed}, escalated={total_escalated}, failed={total_failed}"
    )

    return {
        "total_fixed":     total_fixed,
        "total_escalated": total_escalated,
        "total_failed":    total_failed,
    }


# ── LangGraph node ────────────────────────────────────────────────────────────

def fortify_writeback_node(
    state: AgentState,
    client: FortifyClient,
) -> AgentState:
    """
    LangGraph node: fortify_writeback.

    Reads:  state["_reasoned_groups"]  (or _diff_groups)
            state["_adr_results"]
            state["_all_pr_results"]
            state["release_id"]
            state["escalation_reason"]
    Writes: state["status"]            → "fixed" or "escalated"
            state["audit_trail"]
    """
    groups: list[dict] = (
        state.get("_reasoned_groups")  # type: ignore[attr-defined]
        or state.get("_diff_groups")   # type: ignore[attr-defined]
        or []
    )
    adr_results: list[dict]  = state.get("_adr_results", [])    # type: ignore[attr-defined]
    pr_results:  list[dict]  = state.get("_all_pr_results", []) # type: ignore[attr-defined]
    release_id:  int         = state.get("release_id", 0)
    escalation_reason        = state.get("escalation_reason")

    if not groups:
        logger.warning("[Writeback] No groups in state — nothing to write back")
        state["audit_trail"].append({"node": "fortify_writeback", "status": "skipped"})
        return state

    summary = run_all_writebacks(
        client=client,
        release_id=release_id,
        groups=groups,
        adr_results=adr_results,
        pr_results=pr_results,
        escalation_reason=escalation_reason,
    )

    # Set final pipeline status
    if summary["total_fixed"] > 0:
        state["status"] = "fixed"
    elif summary["total_escalated"] > 0:
        state["status"] = "escalated"

    state["audit_trail"].append({
        "node": "fortify_writeback",
        "status": "ok",
        **summary,
    })

    return state
