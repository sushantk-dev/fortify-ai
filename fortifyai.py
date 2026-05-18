"""
FortifyAI — CLI Entry Point
----------------------------
Usage:
    python fortifyai.py --release <RELEASE_ID>

Iteration 1: loads config, builds graph, prints confirmation, exits.
"""

from __future__ import annotations

import argparse
import sys

from loguru import logger

from config import FortifyAIConfig, load_config
from fortify_client import FortifyClient
from graph import get_compiled_graph
from state import AgentState


# ── Logging setup ─────────────────────────────────────────────────────────────

def configure_logging(verbose: bool = False) -> None:
    """Configure loguru: one line per event, coloured, with timestamps."""
    logger.remove()  # Remove default handler
    level = "DEBUG" if verbose else "INFO"
    logger.add(
        sys.stderr,
        level=level,
        format=(
            "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}</cyan>:<cyan>{line}</cyan> — "
            "<level>{message}</level>"
        ),
        colorize=True,
    )


# ── State factory ─────────────────────────────────────────────────────────────

def initial_state(release_id: int) -> AgentState:
    """Return a fully-typed initial AgentState for a new pipeline run."""
    return AgentState(
        # Input
        release_id=release_id,
        vuln_id=None,
        cve_list=[],

        # Fortify finding
        dependency=None,
        severity=None,
        owasp_2021=None,
        sonatype_explanation=None,
        primary_location=None,
        is_suppressed=False,
        auditor_status=None,
        closed_status=False,

        # Version resolution
        version_candidates=None,
        current_candidate=None,
        candidate_index=0,

        # Context
        pom_location=None,
        calling_files=[],
        calling_code_snippet=None,

        # API diff
        api_diff=None,

        # AI reasoning
        ai_reasoning=None,

        # ADR fix
        adr_result=None,

        # Retry
        retry_count=0,
        last_build_error=None,
        ai_code_fix_applied=False,

        # PR
        pr_result=None,

        # Pipeline control
        status="running",
        skip_reason=None,
        escalation_reason=None,

        # Audit trail
        audit_trail=[],
    )


# ── CLI ───────────────────────────────────────────────────────────────────────

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="fortifyai",
        description="FortifyAI — Automated Security Dependency Remediation",
    )
    parser.add_argument(
        "--release",
        type=int,
        required=True,
        metavar="RELEASE_ID",
        help="Fortify SSC release ID to remediate (e.g. 1723380)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable DEBUG-level logging",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    configure_logging(verbose=args.verbose)

    logger.info("=" * 60)
    logger.info("FortifyAI starting up")
    logger.info(f"  Release ID : {args.release}")
    logger.info("=" * 60)

    # 1. Load and validate configuration
    try:
        config: FortifyAIConfig = load_config()
        logger.info("[Config] ✅ Configuration loaded successfully")
        logger.debug(f"[Config] Fortify base URL : {config.fortify_base_url}")
        logger.debug(f"[Config] GitHub repo      : {config.github_repo}")
        logger.debug(f"[Config] GCP project      : {config.gcp_project}")
        logger.debug(f"[Config] ADR path         : {config.adr_path}")
        logger.debug(f"[Config] Max retries      : {config.max_retries}")
    except Exception as exc:
        logger.error(f"[Config] ❌ Failed to load configuration: {exc}")
        logger.error(
            "Create a .env file from .env.example and fill in all required values."
        )
        return 1

    # 2. Build and compile the LangGraph pipeline
    try:
        graph = get_compiled_graph()
        logger.info("[Graph] ✅ Pipeline graph registered and compiled")
    except Exception as exc:
        logger.error(f"[Graph] ❌ Failed to compile graph: {exc}")
        return 1

    # 3. Construct initial state
    state = initial_state(args.release)
    logger.info(f"[State] ✅ Initial state constructed for release {args.release}")

    # ── Iterations 2–4: Fetch → Triage → Resolve versions ───────────────────
    try:
        client = FortifyClient.from_config(config)
        logger.info("[Client] ✅ FortifyClient initialised")
    except Exception as exc:
        logger.error(f"[Client] ❌ Failed to build FortifyClient: {exc}")
        return 1

    logger.info("─" * 60)

    try:
        raw_vulns = client.get_vulnerabilities(args.release)
        logger.info(f"Fetched {len(raw_vulns)} vulnerabilities")
    except Exception as exc:
        logger.error(f"[Client] ❌ API call failed: {exc}")
        logger.error(
            "Check FORTIFY_BASE_URL and FORTIFY_API_TOKEN in your .env file."
        )
        return 1

    # Triage
    from agents.triage import group_by_dependency
    groups = group_by_dependency(raw_vulns)

    if not groups:
        logger.warning("[Triage] No actionable findings — nothing to remediate")
        return 0

    logger.info("─" * 60)

    # Version resolution
    from agents.version_resolver import resolve_all_groups
    resolved_groups = resolve_all_groups(client, args.release, groups)

    logger.info("─" * 60)

    # Context resolution
    from agents.context import locate_all_groups
    from pathlib import Path
    context_groups = locate_all_groups(Path(config.project_path), resolved_groups)

    logger.info("─" * 60)

    # API diff
    from agents.api_diff import run_api_diff_all_groups
    diff_groups = run_api_diff_all_groups(
        context_groups, Path(config.project_path), config.japicmp_jar_path
    )

    logger.info("─" * 60)

    # AI reasoning
    from agents.ai_reasoning import reason_all_groups
    reasoned_groups = reason_all_groups(diff_groups, config.gcp_project, config.gcp_location)

    logger.info("─" * 60)

    # ADR fix — run for each actionable group
    from agents.adr_fix import run_adr_fix
    for group in reasoned_groups:
        if group.get("next_node") == "escalate":
            logger.warning(
                f"[ADR Fix] Skipping {group['parsed']['artifact_id']} — escalated by AI reasoning"
            )
            continue
        run_adr_fix(
            group,
            adr_path=config.adr_path,
            project_path=config.project_path,
            jira_prefix=config.jira_id_prefix,
        )

    logger.info("─" * 60)
    logger.info("Iteration 11 ✅  Pipeline complete — all iterations implemented")
    logger.info("─" * 60)

    return 0


if __name__ == "__main__":
    sys.exit(main())