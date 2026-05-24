"""
FortifyAI — FastAPI Server
===========================
Exposes every execution combination of the FortifyAI pipeline as REST endpoints.

Execution Modes:
  FULL PIPELINE
    POST /pipeline/live            — Full pipeline, live Fortify API
    POST /pipeline/offline         — Full pipeline, offline JSON report
    POST /pipeline/app-name        — Full pipeline, resolve app name → release

  INDIVIDUAL STAGES (can be called in isolation)
    POST /stages/triage            — Stage 1: filter/group raw vulnerabilities
    POST /stages/version-resolver  — Stage 2: resolve safe version candidates
    POST /stages/context           — Stage 3: locate dep in codebase
    POST /stages/api-diff          — Stage 4: run japicmp API diff
    POST /stages/ai-reasoning      — Stage 5: AI safety verdict
    POST /stages/adr-fix           — Stage 6: invoke adr.py --commit --push
    POST /stages/ai-code-fix       — Stage 7: AI patch for broken call sites
    POST /stages/pr-agent          — Stage 8: create GitHub PR
    POST /stages/fortify-writeback — Stage 9: post outcome comment to SSC

  PARTIAL PIPELINES (stop at a given stage)
    POST /pipeline/until/triage
    POST /pipeline/until/version-resolver
    POST /pipeline/until/context
    POST /pipeline/until/api-diff
    POST /pipeline/until/ai-reasoning
    POST /pipeline/until/adr-fix
    POST /pipeline/until/pr-agent

  UTILITY
    GET  /health                   — liveness probe
    GET  /config/validate          — validate current .env config
    GET  /releases                 — list releases for an app name
    POST /pipeline/dry-run         — full pipeline, skips ADR/PR/writeback side-effects

Run:
    uvicorn api_server:app --host 0.0.0.0 --port 8000 --reload
"""

from __future__ import annotations

import time
import traceback
from pathlib import Path
from typing import Any, Literal, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

# ── Internal imports ──────────────────────────────────────────────────────────
from config import FortifyAIConfig, load_config
from state import AgentState

# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="FortifyAI API",
    description=(
        "REST API exposing every execution combination of the FortifyAI "
        "automated security dependency remediation pipeline."
    ),
    version="1.0.0",
)


# ═══════════════════════════════════════════════════════════════════════════════
# Request / Response models
# ═══════════════════════════════════════════════════════════════════════════════

class ConfigOverrides(BaseModel):
    """Optional per-request overrides for any FortifyAIConfig field."""
    fortify_base_url: Optional[str] = None
    fortify_api_token: Optional[str] = None
    github_token: Optional[str] = None
    github_repo: Optional[str] = None
    project_path: Optional[str] = None
    adr_path: Optional[str] = None
    japicmp_jar_path: Optional[str] = None
    gcp_project: Optional[str] = None
    gcp_location: Optional[str] = None
    max_retries: Optional[int] = Field(default=None, ge=1, le=10)
    jira_id_prefix: Optional[str] = None
    reviewers: Optional[str] = None
    adr_output_dir: Optional[str] = None


# ── Full pipeline ─────────────────────────────────────────────────────────────

class LivePipelineRequest(BaseModel):
    release_id: int = Field(..., description="Fortify SSC release ID to remediate")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class AppNamePipelineRequest(BaseModel):
    app_name: str = Field(..., description="Fortify application name — resolved to app_id then latest release_id")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class AppIdPipelineRequest(BaseModel):
    app_id: int = Field(..., description="Fortify applicationId — skips name lookup, resolves directly to latest release_id")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class OfflinePipelineRequest(BaseModel):
    report_path: str = Field(..., description="Absolute path to Fortify JSON report on disk")
    release_id: int = Field(default=0, description="Release ID override (0 = read from file)")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class DryRunRequest(BaseModel):
    """Full analysis pipeline — ADR/PR/writeback are simulated, not executed."""
    release_id: int = Field(default=0)
    report_path: Optional[str] = Field(default=None, description="Use offline JSON if provided")
    app_name: Optional[str] = Field(default=None, description="Fortify application name (resolved to app_id → release_id)")
    app_id: Optional[int] = Field(default=None, description="Fortify applicationId (skips name lookup)")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


# ── Auth ─────────────────────────────────────────────────────────────────────

class AuthTokenRequest(BaseModel):
    """
    Override credentials per-request. Leave all fields empty to use values from .env.
    Useful for testing a different account without editing config.
    """
    username: Optional[str] = Field(default=None, description="Fortify login username (overrides FORTIFY_USERNAME)")
    password: Optional[str] = Field(default=None, description="Fortify login password (overrides FORTIFY_PASSWORD)")
    scope: Optional[str]    = Field(default=None, description="OAuth scope (default: api-tenant)")
    write_to_env: bool       = Field(default=True, description="Persist the new token to FORTIFY_API_TOKEN in .env")
    env_path: str            = Field(default=".env", description="Path to the .env file to update")


# ── Individual stages ─────────────────────────────────────────────────────────

class TriageRequest(BaseModel):
    raw_vulnerabilities: list[dict] = Field(..., description="Raw Fortify /vulnerabilities response items")


class VersionResolverRequest(BaseModel):
    groups: list[dict] = Field(..., description="Triaged dependency groups from /stages/triage")
    release_id: int = Field(..., description="Fortify release ID for version lookup")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


class ContextRequest(BaseModel):
    groups: list[dict] = Field(..., description="Version-resolved groups")
    project_path: str = Field(..., description="Absolute path to Maven project root")


class ApiDiffRequest(BaseModel):
    groups: list[dict] = Field(..., description="Context-located groups")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    japicmp_jar_path: str = Field(..., description="Absolute path to japicmp fat-jar")


class AiReasoningRequest(BaseModel):
    groups: list[dict] = Field(..., description="API-diff annotated groups")
    gcp_project: str = Field(..., description="GCP project ID for Vertex AI")
    gcp_location: str = Field(default="us-central1")


class AdrFixRequest(BaseModel):
    groups: list[dict] = Field(..., description="AI-reasoned groups")
    adr_path: str = Field(..., description="Absolute path to adr.py")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    jira_prefix: str = Field(default="FORTIFY")


class AiCodeFixRequest(BaseModel):
    groups: list[dict] = Field(..., description="Groups that failed build — need AI patching")
    project_path: str = Field(..., description="Absolute path to Maven project root")
    gcp_project: str = Field(default="")
    gcp_location: str = Field(default="us-central1")


class PrAgentRequest(BaseModel):
    groups: list[dict] = Field(..., description="Reasoned groups")
    adr_results: list[dict] = Field(..., description="Results from /stages/adr-fix")
    release_id: int = Field(..., description="Fortify release ID (used in PR body)")
    github_token: str = Field(..., description="GitHub personal access token")
    github_repo: str = Field(..., description="GitHub repo in owner/repo format")
    reviewers: list[str] = Field(default_factory=list)


class FortifyWritebackRequest(BaseModel):
    groups: list[dict] = Field(..., description="Reasoned groups")
    adr_results: list[dict] = Field(..., description="Results from /stages/adr-fix")
    pr_results: list[dict] = Field(default_factory=list)
    output_dir: str = Field(default="/tmp/fortifyai")


# ── Partial pipeline ──────────────────────────────────────────────────────────

class PartialPipelineRequest(BaseModel):
    release_id: int = Field(default=0, description="Fortify release ID (pick one source)")
    report_path: Optional[str] = Field(default=None, description="Offline JSON report path (skips SSC API)")
    app_name: Optional[str] = Field(default=None, description="Fortify application name (resolved to app_id → release_id)")
    app_id: Optional[int] = Field(default=None, description="Fortify applicationId (skips name lookup, resolves to latest release_id)")
    config: ConfigOverrides = Field(default_factory=ConfigOverrides)


# ── Shared response envelope ──────────────────────────────────────────────────

def ok(data: Any, elapsed: float | None = None) -> dict:
    resp: dict = {"ok": True, "data": data}
    if elapsed is not None:
        resp["elapsed_seconds"] = round(elapsed, 3)
    return resp


def err(detail: str, exc: Exception | None = None) -> JSONResponse:
    body: dict = {"ok": False, "error": detail}
    if exc is not None:
        body["traceback"] = traceback.format_exc()
    return JSONResponse(status_code=500, content=body)


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════

def _apply_overrides(cfg: FortifyAIConfig, overrides: ConfigOverrides) -> FortifyAIConfig:
    """Return a new config with non-None override fields applied."""
    data = cfg.model_dump()
    for field, value in overrides.model_dump().items():
        if value is not None:
            data[field] = value
    return FortifyAIConfig(**data)


def _resolve_vulnerabilities(
    cfg: FortifyAIConfig,
    release_id: int,
    report_path: str | None,
    app_name: str | None,
    app_id: int | None = None,
):
    """
    Returns (client, raw_vulns, resolved_release_id, resolved_app_id).

    Resolution priority:
      1. report_path  — offline mode, no SSC calls
      2. release_id   — direct, fastest
      3. app_id       — skips name lookup, calls GET /releases?limit=1
      4. app_name     — name → app_id → release_id (two API calls)
    """
    from fortify_client import FortifyClient
    from offline_loader import load_report, NullFortifyClient

    if report_path:
        raw_vulns, file_release_id = load_report(report_path)
        effective_release_id = file_release_id if file_release_id else release_id
        client = NullFortifyClient(raw_vulns)
        return client, raw_vulns, effective_release_id, None

    client = FortifyClient.from_config(cfg)
    resolved_app_id: int | None = app_id

    if app_name and not app_id:
        # name → app_id (GET /api/v3/applications?filters=applicationName:<name>)
        app = client.get_application_by_name(app_name)
        resolved_app_id = app["applicationId"]

    if resolved_app_id and not release_id:
        # app_id → latest release_id (GET /api/v3/applications/{id}/releases?limit=1)
        release = client.get_latest_release(resolved_app_id)
        release_id = release["releaseId"]

    if release_id == 0:
        raise ValueError("Provide one of: release_id, app_id, app_name, or report_path")

    raw_vulns = client.get_vulnerabilities(release_id)
    return client, raw_vulns, release_id, resolved_app_id


def _run_full_pipeline(
    cfg: FortifyAIConfig,
    client,
    raw_vulns: list[dict],
    release_id: int,
    dry_run: bool = False,
) -> dict:
    """Execute the full pipeline and return a summary dict."""
    from pathlib import Path
    from agents.triage import group_by_dependency
    from agents.version_resolver import resolve_all_groups
    from agents.context import locate_all_groups
    from agents.api_diff import run_api_diff_all_groups
    from agents.ai_reasoning import reason_all_groups
    from agents.adr_fix import run_adr_fix
    from agents.pr_agent import create_prs_for_all_groups
    from agents.fortify_writeback import run_all_reports
    from state import AdrResult

    project_path = Path(cfg.project_path) if cfg.project_path else Path(".")
    japicmp_path = cfg.japicmp_jar_path or "/nonexistent/japicmp.jar"

    # Stage 1 — triage
    groups = group_by_dependency(raw_vulns)
    if not groups:
        return {"status": "skipped", "reason": "No actionable findings"}

    # Stage 2 — version resolver
    resolved = resolve_all_groups(client, release_id, groups)

    # Stage 3 — context
    context = locate_all_groups(project_path, resolved)

    # Stage 4 — api diff
    diffed = run_api_diff_all_groups(context, project_path, japicmp_path)

    # Stage 5 — ai reasoning
    reasoned = reason_all_groups(diffed, cfg.gcp_project, cfg.gcp_location)

    # Stage 6 — adr fix
    adr_results: list[dict] = []
    for group in reasoned:
        artifact_id = group["parsed"]["artifact_id"]
        if group.get("next_node") == "escalate":
            adr_results.append({
                "artifact_id": artifact_id,
                "result": AdrResult(
                    success=False, branch_name=None, commit_hash=None,
                    build_time_seconds=None, pdf_path=None,
                    error_reason=group.get("escalation_reason", "Escalated by AI reasoning"),
                ),
            })
            continue

        if dry_run or not cfg.adr_path:
            adr_results.append({
                "artifact_id": artifact_id,
                "result": AdrResult(
                    success=False, branch_name=None, commit_hash=None,
                    build_time_seconds=None, pdf_path=None,
                    error_reason="dry_run=True — ADR not invoked" if dry_run else "ADR_PATH not configured",
                ),
            })
        else:
            result = run_adr_fix(
                group, adr_path=cfg.adr_path,
                project_path=str(project_path),
                jira_prefix=cfg.jira_id_prefix,
            )
            adr_results.append({"artifact_id": artifact_id, "result": result})

    # Stage 7 — pr agent
    pr_results = []
    if not dry_run and cfg.github_token and cfg.github_repo:
        pr_results = create_prs_for_all_groups(
            groups=reasoned, adr_results=adr_results,
            release_id=release_id,
            github_token=cfg.github_token,
            github_repo=cfg.github_repo,
            reviewers=cfg.get_reviewers(),
        )

    # Stage 8 — writeback + summary
    if not dry_run:
        summary = run_all_reports(
            groups=reasoned, adr_results=adr_results,
            pr_results=pr_results, output_dir=cfg.adr_output_dir,
        )
    else:
        summary = {"dry_run": True, "groups": len(reasoned)}

    return {
        "release_id": release_id,
        "groups_count": len(reasoned),
        "adr_results": adr_results,
        "pr_results": pr_results,
        "summary": summary,
        "dry_run": dry_run,
    }


# ═══════════════════════════════════════════════════════════════════════════════
# UTILITY ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.get("/health", tags=["Utility"])
def health():
    """Liveness probe — always returns 200 OK."""
    return {"ok": True, "service": "FortifyAI API"}


@app.get("/config/validate", tags=["Utility"])
def config_validate():
    """
    Load and validate the current .env config.
    Returns which required fields are present/missing.
    """
    try:
        cfg = load_config()
    except Exception as exc:
        return JSONResponse(status_code=422, content={"ok": False, "error": str(exc)})

    checks = {
        "fortify_base_url": bool(cfg.fortify_base_url),
        "fortify_api_token": bool(cfg.fortify_api_token),
        "github_token": bool(cfg.github_token),
        "github_repo": bool(cfg.github_repo),
        "project_path": bool(cfg.project_path),
        "adr_path": bool(cfg.adr_path),
        "japicmp_jar_path": bool(cfg.japicmp_jar_path),
        "gcp_project": bool(cfg.gcp_project),
    }
    missing = [k for k, v in checks.items() if not v]
    return ok({"fields": checks, "missing": missing, "ready": len(missing) == 0})


@app.post("/auth/token", tags=["Utility"])
def auth_token(req: AuthTokenRequest = AuthTokenRequest()):
    """
    Fetch a fresh Fortify Bearer token via OAuth2 password grant and
    optionally write it back to `FORTIFY_API_TOKEN` in `.env`.

    Credentials are read from `.env` (`FORTIFY_USERNAME`, `FORTIFY_PASSWORD`,
    `FORTIFY_SCOPE`) unless overridden in the request body.

    Flow:
      POST {FORTIFY_BASE_URL}/oauth/token
        grant_type=password  scope=api-tenant
        username=<from env>  password=<from env>
        security_code=       do_totp=false
      → access_token written to FORTIFY_API_TOKEN in .env (if write_to_env=true)

    Returns:
      access_token, token_type, expires_in, scope
    """
    import time as _time
    t0 = _time.time()
    try:
        from fortify_auth import fetch_token, write_token_to_env
        cfg = load_config()
        token_data = fetch_token(
            cfg,
            username=req.username,
            password=req.password,
            scope=req.scope,
        )
        if req.write_to_env and token_data.get("access_token"):
            write_token_to_env(token_data["access_token"], env_path=req.env_path)
        return ok({
            "access_token": token_data.get("access_token"),
            "token_type":   token_data.get("token_type", "Bearer"),
            "expires_in":   token_data.get("expires_in"),
            "scope":        token_data.get("scope"),
            "written_to_env": req.write_to_env,
            "env_path":     req.env_path,
        }, _time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.get("/releases", tags=["Utility"])
def list_releases(
    app_name: Optional[str] = Query(default=None, description="Fortify application name"),
    app_id: Optional[int] = Query(default=None, description="Fortify applicationId (skips name lookup)"),
):
    """
    List all releases for an application.

    Provide **either** `app_name` or `app_id` as a query parameter.
    Using `app_id` skips the name-lookup API call and is preferred when the ID is known.

    Examples:
      GET /releases?app_name=1038_US_D360-Citi-Triggers-on-Cloud_USIS
      GET /releases?app_id=147266
    """
    try:
        if not app_name and not app_id:
            raise ValueError("Provide either app_name or app_id as a query parameter")
        cfg = load_config()
        from fortify_client import FortifyClient
        client = FortifyClient.from_config(cfg)
        if app_id is None:
            # name → app_id first
            app = client.get_application_by_name(app_name)
            app_id = app["applicationId"]
        releases = client.get_releases(app_id)
        return ok({"app_id": app_id, "app_name": app_name, "releases": releases})
    except Exception as exc:
        return err(str(exc), exc)


@app.get("/resolve/app-name", tags=["Utility"])
def resolve_app_name(
    app_name: str = Query(..., description="Fortify application name to resolve"),
):
    """
    Resolve an application name to its `applicationId` and latest `releaseId`.

    Calls:
      1. GET /api/v3/applications?filters=applicationName:<name>  → applicationId
      2. GET /api/v3/applications/{applicationId}/releases?limit=1 → releaseId

    Returns both IDs so callers can cache the `app_id` and use
    `/pipeline/app-id` on subsequent requests (one fewer API call).
    """
    try:
        cfg = load_config()
        from fortify_client import FortifyClient
        client = FortifyClient.from_config(cfg)
        app = client.get_application_by_name(app_name)
        app_id: int = app["applicationId"]
        release = client.get_latest_release(app_id)
        return ok({
            "app_name": app_name,
            "app_id": app_id,
            "latest_release_id": release["releaseId"],
            "latest_release_name": release.get("releaseName"),
            "latest_release_date": release.get("releaseCreatedDate"),
        })
    except Exception as exc:
        return err(str(exc), exc)


# ═══════════════════════════════════════════════════════════════════════════════
# FULL PIPELINE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/pipeline/live", tags=["Full Pipeline"])
def pipeline_live(req: LivePipelineRequest):
    """
    Run the **complete** FortifyAI pipeline against a live Fortify SSC release.

    Stages: triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
    """
    t0 = time.time()
    try:
        cfg = _apply_overrides(load_config(), req.config)
        client, raw_vulns, release_id, app_id = _resolve_vulnerabilities(
            cfg, req.release_id, None, None
        )
        result = _run_full_pipeline(cfg, client, raw_vulns, release_id)
        return ok(result, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/pipeline/offline", tags=["Full Pipeline"])
def pipeline_offline(req: OfflinePipelineRequest):
    """
    Run the **complete** pipeline from a saved Fortify JSON report (no SSC credentials needed).

    Stages: triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
    """
    t0 = time.time()
    try:
        cfg = _apply_overrides(load_config(), req.config)
        client, raw_vulns, release_id, app_id = _resolve_vulnerabilities(
            cfg, req.release_id, req.report_path, None
        )
        result = _run_full_pipeline(cfg, client, raw_vulns, release_id)
        return ok(result, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/pipeline/app-name", tags=["Full Pipeline"])
def pipeline_app_name(req: AppNamePipelineRequest):
    """
    Run the **complete** pipeline by resolving an application name → `app_id` → latest `release_id`.

    Resolution steps:
      1. GET /api/v3/applications?filters=applicationName:<name>  → `applicationId`
      2. GET /api/v3/applications/{applicationId}/releases?limit=1 → `releaseId`
      3. Full pipeline runs against that `releaseId`

    If you already know the `applicationId`, use `/pipeline/app-id` to skip step 1.

    Stages: (name→app_id→release_id) → triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
    """
    t0 = time.time()
    try:
        cfg = _apply_overrides(load_config(), req.config)
        client, raw_vulns, release_id, app_id = _resolve_vulnerabilities(
            cfg, 0, None, req.app_name
        )
        result = _run_full_pipeline(cfg, client, raw_vulns, release_id)
        result["app_id"] = app_id
        return ok(result, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/pipeline/app-id", tags=["Full Pipeline"])
def pipeline_app_id(req: AppIdPipelineRequest):
    """
    Run the **complete** pipeline using a known Fortify `applicationId`.

    Skips the name-lookup step — one fewer API call vs `/pipeline/app-name`.
    Resolves `app_id → latest release_id` then runs the full pipeline.

    Stages: (release lookup) → triage → version-resolver → context → api-diff →
            ai-reasoning → adr-fix → pr-agent → fortify-writeback
    """
    t0 = time.time()
    try:
        cfg = _apply_overrides(load_config(), req.config)
        client, raw_vulns, release_id, app_id = _resolve_vulnerabilities(
            cfg, 0, None, None, req.app_id
        )
        result = _run_full_pipeline(cfg, client, raw_vulns, release_id)
        result["app_id"] = app_id
        return ok(result, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/pipeline/dry-run", tags=["Full Pipeline"])
def pipeline_dry_run(req: DryRunRequest):
    """
    Run the full analysis pipeline **without** side effects.

    ADR (git commit/push), PR creation, and Fortify writeback are **skipped**.
    Everything up to and including AI reasoning runs normally.
    Useful for previewing what the pipeline would do.
    """
    t0 = time.time()
    try:
        cfg = _apply_overrides(load_config(), req.config)
        client, raw_vulns, release_id, app_id = _resolve_vulnerabilities(
            cfg, req.release_id, req.report_path, req.app_name, getattr(req, "app_id", None)
        )
        result = _run_full_pipeline(cfg, client, raw_vulns, release_id, dry_run=True)
        return ok(result, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


# ═══════════════════════════════════════════════════════════════════════════════
# INDIVIDUAL STAGE ENDPOINTS
# ═══════════════════════════════════════════════════════════════════════════════

@app.post("/stages/triage", tags=["Individual Stages"])
def stage_triage(req: TriageRequest):
    """
    **Stage 1 — Triage**

    Filter and group raw Fortify vulnerability items by dependency.
    Suppressed, closed, and non-OSS findings are dropped.

    Input:  raw_vulnerabilities[]  (direct from Fortify /vulnerabilities API)
    Output: grouped dependency objects ready for version resolution
    """
    t0 = time.time()
    try:
        from agents.triage import group_by_dependency
        groups = group_by_dependency(req.raw_vulnerabilities)
        return ok({"groups": groups, "count": len(groups)}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/version-resolver", tags=["Individual Stages"])
def stage_version_resolver(req: VersionResolverRequest):
    """
    **Stage 2 — Version Resolver**

    For each dependency group, resolve the next-safe and greatest-safe
    upgrade candidates from Fortify recommendations + Maven Central.

    Input:  groups[]       (from /stages/triage)
    Output: groups enriched with version_candidates
    """
    t0 = time.time()
    try:
        cfg = _apply_overrides(load_config(), req.config)
        from fortify_client import FortifyClient
        from agents.version_resolver import resolve_all_groups
        client = FortifyClient.from_config(cfg)
        resolved = resolve_all_groups(client, req.release_id, req.groups)
        return ok({"groups": resolved}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/context", tags=["Individual Stages"])
def stage_context(req: ContextRequest):
    """
    **Stage 3 — Context Gathering**

    Locate each dependency in the codebase: find pom.xml declarations
    (direct or transitive) and all Java files that call the library.

    Input:  groups[]       (from /stages/version-resolver)
            project_path   (absolute path to Maven project root)
    Output: groups enriched with pom_location and calling_files
    """
    t0 = time.time()
    try:
        from agents.context import locate_all_groups
        groups = locate_all_groups(Path(req.project_path), req.groups)
        return ok({"groups": groups}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/api-diff", tags=["Individual Stages"])
def stage_api_diff(req: ApiDiffRequest):
    """
    **Stage 4 — API Diff**

    Download old + new JARs from Maven Central, run japicmp, and map
    breaking changes to calling file line numbers using Java AST analysis.

    Input:  groups[]           (from /stages/context)
            project_path       (absolute path to Maven project root)
            japicmp_jar_path   (absolute path to japicmp fat-jar)
    Output: groups enriched with api_diff (breaking change analysis)
    """
    t0 = time.time()
    try:
        from agents.api_diff import run_api_diff_all_groups
        groups = run_api_diff_all_groups(
            req.groups, Path(req.project_path), req.japicmp_jar_path
        )
        return ok({"groups": groups}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/ai-reasoning", tags=["Individual Stages"])
def stage_ai_reasoning(req: AiReasoningRequest):
    """
    **Stage 5 — AI Reasoning**

    Send calling code, API diff, and changelog to Claude/Gemini via Vertex AI.
    Returns a safety verdict (safe/unsafe), confidence level, and
    at-risk code lines. Routes each group to adr-fix or escalate.

    Input:  groups[]       (from /stages/api-diff)
            gcp_project    (GCP project ID)
            gcp_location   (Vertex AI region, default us-central1)
    Output: groups enriched with ai_reasoning verdict
    """
    t0 = time.time()
    try:
        from agents.ai_reasoning import reason_all_groups
        groups = reason_all_groups(req.groups, req.gcp_project, req.gcp_location)
        return ok({"groups": groups}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/adr-fix", tags=["Individual Stages"])
def stage_adr_fix(req: AdrFixRequest):
    """
    **Stage 6 — ADR Fix**

    Invoke `adr.py --commit JIRA_ID --push` for each actionable group.
    Parses exit code, branch name, commit hash, and PDF path from stdout.

    Input:  groups[]       (from /stages/ai-reasoning)
            adr_path       (absolute path to adr.py)
            project_path   (absolute path to Maven project root)
            jira_prefix    (e.g. "FORTIFY")
    Output: adr_results[] with success/failure per dependency
    """
    t0 = time.time()
    try:
        from agents.adr_fix import run_adr_fix
        from state import AdrResult

        results = []
        for group in req.groups:
            artifact_id = group["parsed"]["artifact_id"]
            if group.get("next_node") == "escalate":
                results.append({
                    "artifact_id": artifact_id,
                    "result": AdrResult(
                        success=False, branch_name=None, commit_hash=None,
                        build_time_seconds=None, pdf_path=None,
                        error_reason=group.get("escalation_reason", "Escalated"),
                    ),
                })
                continue
            result = run_adr_fix(
                group, adr_path=req.adr_path,
                project_path=req.project_path,
                jira_prefix=req.jira_prefix,
            )
            results.append({"artifact_id": artifact_id, "result": result})

        return ok({"adr_results": results}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/ai-code-fix", tags=["Individual Stages"])
def stage_ai_code_fix(req: AiCodeFixRequest):
    """
    **Stage 7 — AI Code Fix**

    When the build fails after an upgrade, send the Maven error and at-risk
    calling code to the LLM for an auto-generated patch. Applied before
    re-running ADR fix (retry loop).

    Input:  groups[]       (groups flagged as needing pre-fix)
            project_path   (absolute path to Maven project root)
            gcp_project
            gcp_location
    Output: groups with ai_code_fix_applied=True and patched source files
    """
    t0 = time.time()
    try:
        from agents.ai_code_fix import ai_code_fix_node
        from state import AgentState

        results = []
        for group in req.groups:
            state = AgentState(
                release_id=0, vuln_id=None, cve_list=[],
                dependency=group.get("parsed"),
                severity=None, owasp_2021=None, sonatype_explanation=None,
                primary_location=None, is_suppressed=False, auditor_status=None,
                closed_status=False, version_candidates=group.get("version_candidates"),
                current_candidate=group.get("current_candidate"),
                candidate_index=group.get("candidate_index", 0),
                pom_location=group.get("pom_location"),
                calling_files=group.get("calling_files", []),
                calling_code_snippet=group.get("calling_code_snippet"),
                api_diff=group.get("api_diff"),
                ai_reasoning=group.get("ai_reasoning"),
                adr_result=None, retry_count=0,
                last_build_error=group.get("last_build_error"),
                ai_code_fix_applied=False,
                pr_result=None, status="running",
                skip_reason=None, escalation_reason=None, audit_trail=[],
                _project_path=req.project_path,
                _gcp_project=req.gcp_project,
                _gcp_location=req.gcp_location,
            )
            updated_state = ai_code_fix_node(
                state, req.project_path, req.gcp_project, req.gcp_location
            )
            results.append({
                "artifact_id": group.get("parsed", {}).get("artifact_id"),
                "ai_code_fix_applied": updated_state.get("ai_code_fix_applied"),
                "status": updated_state.get("status"),
            })

        return ok({"results": results}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/pr-agent", tags=["Individual Stages"])
def stage_pr_agent(req: PrAgentRequest):
    """
    **Stage 8 — PR Agent**

    Create GitHub pull requests for all successfully fixed dependencies.
    Sets title, body, labels, reviewers, and attaches the ADR PDF report.

    Input:  groups[]       (from /stages/ai-reasoning)
            adr_results[]  (from /stages/adr-fix)
            release_id
            github_token
            github_repo
            reviewers[]
    Output: pr_results[] with pr_url and pr_number per dependency
    """
    t0 = time.time()
    try:
        from agents.pr_agent import create_prs_for_all_groups
        pr_results = create_prs_for_all_groups(
            groups=req.groups,
            adr_results=req.adr_results,
            release_id=req.release_id,
            github_token=req.github_token,
            github_repo=req.github_repo,
            reviewers=req.reviewers,
        )
        return ok({"pr_results": pr_results}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


@app.post("/stages/fortify-writeback", tags=["Individual Stages"])
def stage_fortify_writeback(req: FortifyWritebackRequest):
    """
    **Stage 9 — Fortify Writeback**

    Post the fix outcome (branch, PR URL, version bumped) as a comment
    back to each Fortify finding. Also generates escalation reports for
    findings that could not be auto-remediated.

    Input:  groups[]       (from /stages/ai-reasoning)
            adr_results[]  (from /stages/adr-fix)
            pr_results[]   (from /stages/pr-agent)
            output_dir     (directory for PDF reports and logs)
    Output: summary with total_fixed / total_escalated / total_failed
    """
    t0 = time.time()
    try:
        from agents.fortify_writeback import run_all_reports
        summary = run_all_reports(
            groups=req.groups,
            adr_results=req.adr_results,
            pr_results=req.pr_results,
            output_dir=req.output_dir,
        )
        return ok({"summary": summary}, time.time() - t0)
    except Exception as exc:
        return err(str(exc), exc)


# ═══════════════════════════════════════════════════════════════════════════════
# PARTIAL PIPELINE ENDPOINTS  (stop at a given stage)
# ═══════════════════════════════════════════════════════════════════════════════

StageLabel = Literal[
    "triage", "version-resolver", "context",
    "api-diff", "ai-reasoning", "adr-fix", "pr-agent",
]

STAGE_ORDER: list[StageLabel] = [
    "triage", "version-resolver", "context",
    "api-diff", "ai-reasoning", "adr-fix", "pr-agent",
]


def _run_until(
    cfg: FortifyAIConfig,
    client,
    raw_vulns: list[dict],
    release_id: int,
    stop_after: StageLabel,
) -> dict:
    """Run the pipeline and stop (inclusive) at `stop_after`."""
    from pathlib import Path
    from agents.triage import group_by_dependency
    from agents.version_resolver import resolve_all_groups
    from agents.context import locate_all_groups
    from agents.api_diff import run_api_diff_all_groups
    from agents.ai_reasoning import reason_all_groups
    from agents.adr_fix import run_adr_fix
    from agents.pr_agent import create_prs_for_all_groups
    from state import AdrResult

    idx = STAGE_ORDER.index(stop_after)
    project_path = Path(cfg.project_path) if cfg.project_path else Path(".")

    result: dict = {"release_id": release_id, "stopped_after": stop_after}

    # Stage 0 — triage
    groups = group_by_dependency(raw_vulns)
    result["groups"] = groups
    result["groups_count"] = len(groups)
    if idx == 0 or not groups:
        return result

    # Stage 1 — version resolver
    resolved = resolve_all_groups(client, release_id, groups)
    result["groups"] = resolved
    if idx == 1:
        return result

    # Stage 2 — context
    context_groups = locate_all_groups(project_path, resolved)
    result["groups"] = context_groups
    if idx == 2:
        return result

    # Stage 3 — api diff
    diff_groups = run_api_diff_all_groups(
        context_groups, project_path,
        cfg.japicmp_jar_path or "/nonexistent/japicmp.jar",
    )
    result["groups"] = diff_groups
    if idx == 3:
        return result

    # Stage 4 — ai reasoning
    reasoned = reason_all_groups(diff_groups, cfg.gcp_project, cfg.gcp_location)
    result["groups"] = reasoned
    if idx == 4:
        return result

    # Stage 5 — adr fix
    adr_results: list[dict] = []
    for group in reasoned:
        artifact_id = group["parsed"]["artifact_id"]
        if group.get("next_node") == "escalate" or not cfg.adr_path:
            adr_results.append({
                "artifact_id": artifact_id,
                "result": AdrResult(
                    success=False, branch_name=None, commit_hash=None,
                    build_time_seconds=None, pdf_path=None,
                    error_reason="Escalated or ADR_PATH not set",
                ),
            })
        else:
            adr_results.append({
                "artifact_id": artifact_id,
                "result": run_adr_fix(
                    group, adr_path=cfg.adr_path,
                    project_path=str(project_path),
                    jira_prefix=cfg.jira_id_prefix,
                ),
            })
    result["adr_results"] = adr_results
    if idx == 5:
        return result

    # Stage 6 — pr agent
    pr_results = []
    if cfg.github_token and cfg.github_repo:
        pr_results = create_prs_for_all_groups(
            groups=reasoned, adr_results=adr_results,
            release_id=release_id,
            github_token=cfg.github_token,
            github_repo=cfg.github_repo,
            reviewers=cfg.get_reviewers(),
        )
    result["pr_results"] = pr_results
    return result


def _make_partial_endpoint(stop_after: StageLabel):
    """Factory that returns a FastAPI route handler for each partial pipeline."""
    async def handler(req: PartialPipelineRequest):
        t0 = time.time()
        try:
            cfg = _apply_overrides(load_config(), req.config)
            client, raw_vulns, release_id, app_id = _resolve_vulnerabilities(
                cfg, req.release_id, req.report_path, req.app_name, getattr(req, "app_id", None)
            )
            result = _run_until(cfg, client, raw_vulns, release_id, stop_after)
            return ok(result, time.time() - t0)
        except Exception as exc:
            return err(str(exc), exc)

    handler.__name__ = f"pipeline_until_{stop_after.replace('-', '_')}"
    return handler


for _stage in STAGE_ORDER:
    _descriptions = {
        "triage":           "Run only **Stage 1 — Triage**. Returns filtered & grouped dependency objects.",
        "version-resolver": "Run up to **Stage 2 — Version Resolver**. Returns groups enriched with safe version candidates.",
        "context":          "Run up to **Stage 3 — Context**. Returns groups with pom locations and calling files.",
        "api-diff":         "Run up to **Stage 4 — API Diff**. Returns groups with breaking-change analysis.",
        "ai-reasoning":     "Run up to **Stage 5 — AI Reasoning**. Returns groups with safety verdicts. No side-effects.",
        "adr-fix":          "Run up to **Stage 6 — ADR Fix**. Commits and pushes version bumps to git.",
        "pr-agent":         "Run up to **Stage 7 — PR Agent**. Creates GitHub PRs. No Fortify writeback.",
    }
    app.add_api_route(
        path=f"/pipeline/until/{_stage}",
        endpoint=_make_partial_endpoint(_stage),
        methods=["POST"],
        tags=["Partial Pipelines"],
        summary=f"Pipeline → stop after {_stage}",
        description=_descriptions[_stage],
    )


# ═══════════════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("api_server:app", host="0.0.0.0", port=8000, reload=True)