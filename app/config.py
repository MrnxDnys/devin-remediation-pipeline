"""Central configuration, loaded from environment / .env.local / .env.

Two run modes:
  live    - real Devin v3 Sessions API + real GitHub (needs a cog_ service-user key).
  replay  - in-process fake Devin + no GitHub writes, so a reviewer can run the whole
            loop at their desk with no key/credits. This is the "simulate" path.
"""
from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=(".env", ".env.local"),  # .env.local wins (loaded last)
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # ---- Devin (v3 org-scoped Sessions API, service-user `cog_` auth) ----
    devin_api_key: str = "cog_replace_me"
    devin_api_base: str = "https://api.devin.ai/v3"
    devin_org_id: str = "org-replace_me"
    devin_mode: str = "replay"  # "live" | "replay"
    devin_max_acu: int | None = 10  # per-session budget guardrail
    # One branching Playbook: dependency-upgrade / code-fix / dismiss-with-evidence.
    devin_playbook_id: str = ""

    # ---- GitHub (Dependabot/scan issue feed + issue write-back) ----
    github_token: str = ""
    github_repo: str = "MrnxDnys/superset"
    github_webhook_secret: str = "change_me"

    # ---- Trigger ----
    # Findings are filed as issues carrying this label; `issues.labeled` fires the pipeline.
    devin_trigger_label: str = "devin-auto"
    devin_failed_label: str = "devin-failed"

    # ---- Scanner (dependency findings) ----
    max_issues_per_scan: int = 5
    scan_target_files: str = "requirements/base.txt"
    scan_ref: str = "master"
    scan_npm: bool = True
    scan_npm_dir: str = "superset-frontend"

    # ---- Orchestrator behaviour / governance ----
    max_retries: int = 1
    poll_interval_seconds: int = 15
    session_timeout_seconds: int = 1800

    # ---- Storage ----
    db_path: str = "data/state.db"

    @property
    def is_live(self) -> bool:
        return self.devin_mode.strip().lower() == "live"


settings = Settings()
