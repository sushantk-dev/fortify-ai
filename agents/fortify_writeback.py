"""
FortifyAI — Escalation Report Writer (replaces Fortify Writeback)
------------------------------------------------------------------
Behaviour change:
  - NO comments are posted back to Fortify SSC (writeback removed entirely)
  - Escalated groups are written to a local folder as individual report files
  - Fixed groups are logged to console only

Escalation report file:
  {output_dir}/escalation_{artifact_id}_{timestamp}.txt

File content:
  [FortifyAI] Escalated — manual action required
  Dependency: org.springframework:spring-context 5.3.31
  CVEs:       CVE-2024-38820, CVE-2025-22233
  Reason:     No safe version available from Fortify recommendations
  Tried:      (none)
  ...

Console output:
  [Report] ✅ spring-context fixed — branch: feature/FORTIFY-a4105c54_fix_20260517
  [Report] 📄 Escalation report written: escalation_no-fix-available_20260523_160000.txt
  [Report] ✅ Done — fixed=2, escalated=1
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from loguru import logger

from state import AgentState


# ── Report content builders ───────────────────────────────────────────────────

def _fixed_summary(
    group: dict,
    adr_result: dict,
    pr_result: dict,
) -> str:
    """One-line console summary for a successfully fixed dependency."""
    parsed      = group["parsed"]
    artifact_id = parsed["artifact_id"]
    current_ver = parsed["current_version"]
    candidate   = group.get("current_candidate") or (
        group.get("version_candidates", {}).get("candidates", ["?"])[0]
    )
    branch      = adr_result.get("branch_name", "unknown")
    pr_url      = pr_result.get("pr_url", "")
    pr_part     = f" | PR: {pr_url}" if pr_url else ""
    return (
        f"{artifact_id} {current_ver} → {candidate} "
        f"| branch: {branch}{pr_part}"
    )


def _escalation_report(
    group: dict,
    escalation_reason: Optional[str],
    adr_results: list[dict],
) -> str:
    """
    Build the full escalation report text for one dependency group.
    Written to disk as a plain-text file.
    """
    parsed      = group["parsed"]
    group_id    = parsed["group_id"]
    artifact_id = parsed["artifact_id"]
    current_ver = parsed["current_version"]
    cves        = group.get("cves", [])
    candidates  = group.get("version_candidates", {}).get("candidates", [])
    tried_str   = ", ".join(candidates) if candidates else "(none)"
    reason      = (
        escalation_reason
        or group.get("escalate_reason")
        or "Automated fix was not possible"
    )

    # Gather retry attempts from adr_results if available
    adr = next(
        (r["result"] for r in adr_results
         if r["artifact_id"] == artifact_id),
        {}
    )
    build_error = adr.get("error_reason", "")

    ai_reasoning = group.get("ai_reasoning", {})
    confidence   = ai_reasoning.get("confidence", "")
    at_risk      = ai_reasoning.get("at_risk_lines", [])

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "=" * 60,
        "[FortifyAI] Escalated — manual action required",
        "=" * 60,
        "",
        f"Dependency:  {group_id}:{artifact_id}",
        f"Version:     {current_ver}",
        f"CVEs:        {', '.join(cves) or '(see Fortify finding)'}",
        f"OWASP:       {group.get('owasp_2021', 'A06:2021')}",
        f"Severity:    {group.get('severity', 'Unknown')}",
        "",
        "── Escalation Reason ──────────────────────────────────",
        reason,
        "",
        "── What Was Tried ─────────────────────────────────────",
        f"Candidates:  {tried_str}",
    ]

    if confidence:
        lines += [f"AI confidence: {confidence}"]
    if at_risk:
        lines += [f"At-risk lines: {', '.join(at_risk[:5])}"]
    if build_error:
        lines += [
            "",
            "── Last Build Error ───────────────────────────────────",
            build_error[:2000],
        ]

    lines += [
        "",
        "── Next Steps ─────────────────────────────────────────",
        "  1. Review the Sonatype recommendation in Fortify SSC",
        "  2. Check whether a patched version exists on Maven Central",
        "  3. Consider a mitigating control if no safe version is available",
        "  4. Contact the dependency maintainer if the CVE is unpatched",
        "  5. Manually update the pom.xml and run mvn clean verify",
        "",
        f"Timestamp:   {ts}",
        "=" * 60,
    ]

    return "\n".join(lines)


# ── File writer ────────────────────────────────────────────────────────────────

def write_escalation_report(
    group: dict,
    escalation_reason: Optional[str],
    adr_results: list[dict],
    output_dir: str,
) -> Optional[str]:
    """
    Write the escalation report to {output_dir}/escalation_{artifact_id}_{ts}.txt.
    Returns the file path on success, None on failure.
    """
    artifact_id = group["parsed"]["artifact_id"]
    ts          = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename    = f"escalation_{artifact_id}_{ts}.txt"

    out_dir = Path(output_dir)
    try:
        out_dir.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        logger.error(f"[Report] Cannot create output dir {output_dir}: {exc}")
        return None

    file_path = out_dir / filename
    content   = _escalation_report(group, escalation_reason, adr_results)

    try:
        file_path.write_text(content, encoding="utf-8")
        logger.info(f"[Report] 📄 Escalation report written: {file_path}")
        return str(file_path)
    except OSError as exc:
        logger.error(f"[Report] Failed to write {file_path}: {exc}")
        return None


# ── Main dispatch ─────────────────────────────────────────────────────────────

def run_all_reports(
    groups: list[dict],
    adr_results: list[dict],
    pr_results: list[dict],
    output_dir: str,
    escalation_reason: Optional[str] = None,
) -> dict:
    """
    For each group:
      - Fixed   → log to console
      - Escalated → write report file to output_dir

    Returns summary dict: total_fixed, total_escalated, total_failed,
                          escalation_files (list of written paths)
    """
    adr_by_artifact = {r["artifact_id"]: r["result"] for r in adr_results}

    pr_by_artifact: dict[str, dict] = {}
    pr_idx = 0
    for g in groups:
        art = g["parsed"]["artifact_id"]
        if adr_by_artifact.get(art, {}).get("success") and pr_idx < len(pr_results):
            pr_by_artifact[art] = pr_results[pr_idx]
            pr_idx += 1

    total_fixed      = 0
    total_escalated  = 0
    total_failed     = 0
    escalation_files: list[str] = []

    for group in groups:
        art        = group["parsed"]["artifact_id"]
        adr_result = adr_by_artifact.get(art, {})
        pr_result  = pr_by_artifact.get(art, {})

        if adr_result.get("success"):
            summary = _fixed_summary(group, adr_result, pr_result)
            logger.info(f"[Report] ✅ {summary}")
            total_fixed += 1
        else:
            reason = (
                group.get("escalate_reason")
                or escalation_reason
                or adr_result.get("error_reason")
                or "Automated fix was not possible"
            )
            path = write_escalation_report(
                group, reason, adr_results, output_dir
            )
            if path:
                total_escalated += 1
                escalation_files.append(path)
            else:
                total_failed += 1

    logger.info(
        f"[Report] ✅ Done — "
        f"fixed={total_fixed}, "
        f"escalated={total_escalated}, "
        f"failed={total_failed}"
    )
    if escalation_files:
        logger.info(f"[Report] Escalation reports in: {output_dir}")

    return {
        "total_fixed":       total_fixed,
        "total_escalated":   total_escalated,
        "total_failed":      total_failed,
        "escalation_files":  escalation_files,
    }


# ── LangGraph node ────────────────────────────────────────────────────────────

def fortify_writeback_node(
    state: AgentState,
    output_dir: str,
) -> AgentState:
    """
    LangGraph node: fortify_writeback (now an escalation report writer).

    Reads:  state["_reasoned_groups"]
            state["_adr_results"]
            state["_all_pr_results"]
            state["escalation_reason"]
    Writes: state["status"]            → "fixed" or "escalated"
            state["_escalation_files"] → list of written report paths
            state["audit_trail"]
    """
    groups: list[dict] = (
        state.get("_reasoned_groups")  # type: ignore[attr-defined]
        or state.get("_diff_groups")   # type: ignore[attr-defined]
        or []
    )
    adr_results: list[dict] = state.get("_adr_results", [])    # type: ignore[attr-defined]
    pr_results:  list[dict] = state.get("_all_pr_results", []) # type: ignore[attr-defined]
    escalation_reason       = state.get("escalation_reason")

    if not groups:
        logger.warning("[Report] No groups in state — nothing to report")
        state["audit_trail"].append({"node": "fortify_writeback", "status": "skipped"})
        return state

    summary = run_all_reports(
        groups=groups,
        adr_results=adr_results,
        pr_results=pr_results,
        output_dir=output_dir,
        escalation_reason=escalation_reason,
    )

    if summary["total_fixed"] > 0:
        state["status"] = "fixed"
    if summary["total_escalated"] > 0:
        state["status"] = "escalated"

    state["_escalation_files"] = summary["escalation_files"]  # type: ignore[typeddict-unknown-key]
    state["audit_trail"].append({
        "node": "fortify_writeback",
        "status": "ok",
        **{k: v for k, v in summary.items() if k != "escalation_files"},
        "escalation_files": summary["escalation_files"],
    })

    return state