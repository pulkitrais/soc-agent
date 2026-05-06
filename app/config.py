"""
Sentinel Investigator - Application Configuration
Centralised settings management using pydantic-settings.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application-wide settings loaded from environment / .env file."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── App meta ──────────────────────────────────────────────────────────────
    app_name: str = "Sentinel Investigator"
    app_version: str = "1.0.0"
    debug: bool = False
    log_level: str = "INFO"

    # ── Azure Auth ────────────────────────────────────────────────────────────
    azure_auth_method: Literal["device_code", "service_principal", "managed_identity"] = (
        "device_code"
    )
    azure_tenant_id: str = ""
    azure_client_id: str = ""
    azure_client_secret: str = ""

    # ── Sentinel workspace defaults ───────────────────────────────────────────
    sentinel_workspace_id: str = ""
    sentinel_resource_group: str = ""
    sentinel_subscription_id: str = ""

    # ── OpenAI ────────────────────────────────────────────────────────────────
    openai_api_key: str = ""
    openai_model: str = "gpt-4o"

    # ── Threat Intel ─────────────────────────────────────────────────────────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ── Storage ───────────────────────────────────────────────────────────────
    data_dir: str = "data"

    @field_validator("log_level")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        upper = v.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return upper

    @property
    def sessions_dir(self) -> Path:
        return Path(self.data_dir) / "sessions"

    @property
    def exports_dir(self) -> Path:
        return Path(self.data_dir) / "exports"

    @property
    def query_library_dir(self) -> Path:
        return Path(self.data_dir) / "query_library"

    def ensure_data_dirs(self) -> None:
        """Create data directories if they don't exist."""
        for d in (self.sessions_dir, self.exports_dir, self.query_library_dir):
            d.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return cached application settings (singleton)."""
    settings = Settings()
    settings.ensure_data_dirs()
    return settings
