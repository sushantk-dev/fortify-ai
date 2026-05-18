"""
FortifyAI Configuration
-----------------------
All environment variables loaded via Pydantic BaseSettings.
Copy .env.example → .env and fill in your values before running.
"""

from pydantic_settings import BaseSettings
from pydantic import Field


class FortifyAIConfig(BaseSettings):
    # ── Fortify SSC ──────────────────────────────────────────────────────────
    fortify_base_url: str = Field(
        ...,
        description="Fortify SSC base URL, e.g. https://your-instance.fortify.com",
    )
    fortify_api_token: str = Field(
        ...,
        description="Fortify SSC API token (Bearer token)",
    )

    # ── GitHub ───────────────────────────────────────────────────────────────
    github_token: str = Field(
        ...,
        description="GitHub personal access token with repo + PR permissions",
    )
    github_repo: str = Field(
        ...,
        description="Target GitHub repo in owner/repo format, e.g. acme/backend",
    )

    # ── Project / ADR ────────────────────────────────────────────────────────
    project_path: str = Field(
        ...,
        description="Absolute path to the Maven project root on disk",
    )
    adr_path: str = Field(
        ...,
        description="Absolute path to adr.py (Automated Dependency Remediation script)",
    )
    japicmp_jar_path: str = Field(
        ...,
        description="Absolute path to japicmp fat-jar for API diff analysis",
    )

    # ── GCP / Vertex AI ──────────────────────────────────────────────────────
    gcp_project: str = Field(
        ...,
        description="GCP project ID for Vertex AI, e.g. my-gcp-project-123",
    )
    gcp_location: str = Field(
        default="us-central1",
        description="GCP region for Vertex AI endpoints",
    )

    # ── Pipeline behaviour ───────────────────────────────────────────────────
    max_retries: int = Field(
        default=3,
        description="Max AI code-fix retry attempts before escalating",
        ge=1,
        le=10,
    )
    jira_id_prefix: str = Field(
        default="FORTIFY",
        description="Prefix used when generating commit/branch JIRA identifiers",
    )
    reviewers: list[str] = Field(
        default=[],
        description="GitHub usernames to auto-assign on high-confidence PRs",
    )

    # ── Optional ADR output path ─────────────────────────────────────────────
    adr_output_dir: str = Field(
        default="/tmp/fortifyai",
        description="Local directory where ADR PDF reports and logs are written",
    )

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        # Allow reading from environment even if .env is absent
        case_sensitive = False


def load_config() -> FortifyAIConfig:
    """Load and validate config. Raises ValidationError on missing required vars."""
    return FortifyAIConfig()
