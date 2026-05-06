"""
Workspace Manager - handles multiple Sentinel workspace configurations.
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

WORKSPACES_FILE = "workspaces.json"


@dataclass
class WorkspaceConfig:
    """Represents a single Log Analytics / Sentinel workspace."""

    name: str
    workspace_id: str
    subscription_id: str = ""
    resource_group: str = ""
    location: str = ""
    is_default: bool = False

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "WorkspaceConfig":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


class WorkspaceManager:
    """Manages a list of Sentinel workspaces persisted to disk."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._workspaces: list[WorkspaceConfig] = []
        self._storage_path = self._settings.query_library_dir / WORKSPACES_FILE
        self._load()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def add_workspace(self, config: WorkspaceConfig) -> None:
        if any(w.workspace_id == config.workspace_id for w in self._workspaces):
            logger.info("Workspace %s already exists, updating.", config.workspace_id)
            self._workspaces = [
                config if w.workspace_id == config.workspace_id else w
                for w in self._workspaces
            ]
        else:
            self._workspaces.append(config)

        # Ensure only one default
        if config.is_default:
            for w in self._workspaces:
                if w.workspace_id != config.workspace_id:
                    w.is_default = False

        self._save()

    def remove_workspace(self, workspace_id: str) -> bool:
        original = len(self._workspaces)
        self._workspaces = [w for w in self._workspaces if w.workspace_id != workspace_id]
        if len(self._workspaces) < original:
            self._save()
            return True
        return False

    def list_workspaces(self) -> list[WorkspaceConfig]:
        return list(self._workspaces)

    def get_default(self) -> Optional[WorkspaceConfig]:
        for w in self._workspaces:
            if w.is_default:
                return w
        # Fall back to settings
        ws_id = self._settings.sentinel_workspace_id
        if ws_id:
            return WorkspaceConfig(
                name="Default (from env)",
                workspace_id=ws_id,
                subscription_id=self._settings.sentinel_subscription_id,
                resource_group=self._settings.sentinel_resource_group,
                is_default=True,
            )
        return None

    def set_default(self, workspace_id: str) -> bool:
        for w in self._workspaces:
            w.is_default = w.workspace_id == workspace_id
        self._save()
        return any(w.workspace_id == workspace_id for w in self._workspaces)

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._storage_path.exists():
            try:
                data = json.loads(self._storage_path.read_text())
                self._workspaces = [WorkspaceConfig.from_dict(d) for d in data]
            except Exception as exc:
                logger.warning("Failed to load workspaces: %s", exc)
                self._workspaces = []

    def _save(self) -> None:
        try:
            self._storage_path.write_text(
                json.dumps([w.to_dict() for w in self._workspaces], indent=2)
            )
        except Exception as exc:
            logger.error("Failed to save workspaces: %s", exc)
