"""
Investigation Session Tracker
Records analyst activity, notes, query results, and evidence during an investigation.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pandas as pd

from app.config import get_settings

logger = logging.getLogger(__name__)


@dataclass
class EvidenceItem:
    """A single piece of evidence collected during an investigation."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    item_type: str = "note"  # note | query | query_result | enrichment | alert
    title: str = ""
    content: str = ""  # For notes / query text
    data: dict[str, Any] = field(default_factory=dict)  # For structured data
    tags: list[str] = field(default_factory=list)
    analyst: str = "analyst"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "EvidenceItem":
        return cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})


@dataclass
class InvestigationSession:
    """Represents a complete investigation session."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    title: str = "Untitled Investigation"
    description: str = ""
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    analyst: str = "analyst"
    status: str = "open"  # open | in_progress | closed | escalated
    severity: str = "medium"  # low | medium | high | critical
    tags: list[str] = field(default_factory=list)
    evidence: list[EvidenceItem] = field(default_factory=list)
    entities: dict[str, list[str]] = field(default_factory=dict)  # users, ips, hashes, etc.
    timeline: list[dict[str, Any]] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "InvestigationSession":
        evidence_raw = d.pop("evidence", [])
        inst = cls(**{k: v for k, v in d.items() if k in cls.__dataclass_fields__})
        inst.evidence = [EvidenceItem.from_dict(e) for e in evidence_raw]
        return inst


class SessionManager:
    """Create, load, save, and list investigation sessions."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._sessions_dir = self._settings.sessions_dir
        self._sessions_dir.mkdir(parents=True, exist_ok=True)

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def create(
        self,
        title: str = "New Investigation",
        description: str = "",
        severity: str = "medium",
        analyst: str = "analyst",
    ) -> InvestigationSession:
        session = InvestigationSession(
            title=title,
            description=description,
            severity=severity,
            analyst=analyst,
        )
        self._save_session(session)
        return session

    def load(self, session_id: str) -> Optional[InvestigationSession]:
        path = self._session_path(session_id)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
            return InvestigationSession.from_dict(data)
        except Exception as exc:
            logger.error("Failed to load session %s: %s", session_id, exc)
            return None

    def save(self, session: InvestigationSession) -> None:
        session.updated_at = datetime.now(timezone.utc).isoformat()
        self._save_session(session)

    def delete(self, session_id: str) -> bool:
        path = self._session_path(session_id)
        if path.exists():
            path.unlink()
            return True
        return False

    def list_sessions(self) -> list[dict[str, Any]]:
        """Return lightweight metadata for all sessions (no evidence data)."""
        sessions = []
        for path in sorted(self._sessions_dir.glob("*.json"), reverse=True):
            try:
                data = json.loads(path.read_text())
                sessions.append({
                    "id": data.get("id"),
                    "title": data.get("title"),
                    "status": data.get("status"),
                    "severity": data.get("severity"),
                    "created_at": data.get("created_at"),
                    "updated_at": data.get("updated_at"),
                    "analyst": data.get("analyst"),
                    "evidence_count": len(data.get("evidence", [])),
                })
            except Exception as exc:
                logger.warning("Could not read session file %s: %s", path, exc)
        return sessions

    # ── Evidence helpers ──────────────────────────────────────────────────────

    def add_note(
        self,
        session: InvestigationSession,
        content: str,
        title: str = "Analyst Note",
        tags: list[str] | None = None,
    ) -> EvidenceItem:
        item = EvidenceItem(
            item_type="note",
            title=title,
            content=content,
            tags=tags or [],
        )
        session.evidence.append(item)
        self._add_timeline_event(session, f"Note added: {title}")
        self.save(session)
        return item

    def add_query_result(
        self,
        session: InvestigationSession,
        query_name: str,
        kql: str,
        df: Optional[pd.DataFrame],
        row_count: int = 0,
    ) -> EvidenceItem:
        item = EvidenceItem(
            item_type="query_result",
            title=f"Query: {query_name}",
            content=kql,
            data={
                "row_count": row_count,
                "preview": df.head(10).to_dict("records") if df is not None else [],
            },
        )
        session.evidence.append(item)
        self._add_timeline_event(session, f"Query executed: {query_name} → {row_count} rows")
        self.save(session)
        return item

    def add_enrichment(
        self,
        session: InvestigationSession,
        entity: str,
        enrichment_data: dict[str, Any],
    ) -> EvidenceItem:
        item = EvidenceItem(
            item_type="enrichment",
            title=f"Enrichment: {entity}",
            content=json.dumps(enrichment_data, indent=2),
            data=enrichment_data,
        )
        session.evidence.append(item)
        self._add_timeline_event(session, f"Entity enriched: {entity}")
        self.save(session)
        return item

    def add_entity(
        self,
        session: InvestigationSession,
        entity_type: str,
        value: str,
    ) -> None:
        """Track an entity (user / IP / hash / device) in the session."""
        if entity_type not in session.entities:
            session.entities[entity_type] = []
        if value not in session.entities[entity_type]:
            session.entities[entity_type].append(value)
        self.save(session)

    # ── Internal ──────────────────────────────────────────────────────────────

    def _save_session(self, session: InvestigationSession) -> None:
        path = self._session_path(session.id)
        path.write_text(json.dumps(session.to_dict(), indent=2, default=str))

    def _session_path(self, session_id: str) -> Path:
        return self._sessions_dir / f"{session_id}.json"

    @staticmethod
    def _add_timeline_event(session: InvestigationSession, message: str) -> None:
        session.timeline.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": message,
        })
