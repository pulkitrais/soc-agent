"""
Saved Query Library
Persist and retrieve analyst-authored KQL queries to/from disk.
"""

from __future__ import annotations

import json
import logging
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

LIBRARY_FILE = "saved_queries.json"


@dataclass
class SavedQuery:
    """A single saved KQL query with metadata."""

    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = ""
    description: str = ""
    kql: str = ""
    tags: list[str] = field(default_factory=list)
    author: str = "analyst"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    category: str = "general"  # general | playbook | hunting | investigation

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "SavedQuery":
        valid_fields = cls.__dataclass_fields__.keys()
        return cls(**{k: v for k, v in data.items() if k in valid_fields})


# Built-in starter queries shown to all users
BUILTIN_QUERIES: list[SavedQuery] = [
    SavedQuery(
        id="builtin-001",
        name="Failed Logons (Last 24h)",
        description="All Event ID 4625 failures in the last day",
        kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName
| order by TimeGenerated desc
| take 500""",
        tags=["authentication", "failed-logon"],
        category="general",
    ),
    SavedQuery(
        id="builtin-002",
        name="Risky Sign-ins (Azure AD)",
        description="Sign-ins flagged with medium/high risk",
        kql="""SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelAggregated in ("medium", "high")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, RiskDetail
| order by TimeGenerated desc
| take 500""",
        tags=["azure-ad", "sign-in", "risky"],
        category="general",
    ),
    SavedQuery(
        id="builtin-003",
        name="Suspicious PowerShell",
        description="PowerShell with encoded/obfuscated commands",
        kql="""DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "powershell.exe"
| where ProcessCommandLine has_any ("-EncodedCommand", "-enc", "-e ", "Invoke-Expression", "IEX", "DownloadString")
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
| order by Timestamp desc
| take 500""",
        tags=["powershell", "obfuscation", "defense-evasion"],
        category="hunting",
    ),
    SavedQuery(
        id="builtin-004",
        name="New Local Admin Created",
        description="Event ID 4732 - user added to local admins group",
        kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4732
| where TargetUserName =~ "Administrators"
| project TimeGenerated, Computer, SubjectUserName, MemberName
| order by TimeGenerated desc""",
        tags=["privilege-escalation", "admin"],
        category="playbook",
    ),
]


class QueryLibrary:
    """Manages saved queries with disk persistence."""

    def __init__(self) -> None:
        self._settings = get_settings()
        self._path = self._settings.query_library_dir / LIBRARY_FILE
        self._queries: list[SavedQuery] = []
        self._load()

    # ── CRUD ──────────────────────────────────────────────────────────────────

    def save(self, query: SavedQuery) -> SavedQuery:
        """Add or update a query (matched by id)."""
        query.updated_at = datetime.now(timezone.utc).isoformat()
        existing_ids = {q.id for q in self._queries}
        if query.id in existing_ids:
            self._queries = [query if q.id == query.id else q for q in self._queries]
        else:
            self._queries.append(query)
        self._persist()
        return query

    def delete(self, query_id: str) -> bool:
        original = len(self._queries)
        self._queries = [q for q in self._queries if q.id != query_id]
        if len(self._queries) < original:
            self._persist()
            return True
        return False

    def get(self, query_id: str) -> Optional[SavedQuery]:
        return next((q for q in self._queries if q.id == query_id), None)

    def list_all(self, include_builtins: bool = True) -> list[SavedQuery]:
        result = list(self._queries)
        if include_builtins:
            # Prepend builtins, avoiding duplicates
            user_ids = {q.id for q in self._queries}
            result = [b for b in BUILTIN_QUERIES if b.id not in user_ids] + result
        return result

    def search(self, term: str) -> list[SavedQuery]:
        term_lower = term.lower()
        return [
            q
            for q in self.list_all()
            if term_lower in q.name.lower()
            or term_lower in q.description.lower()
            or any(term_lower in tag for tag in q.tags)
        ]

    # ── Persistence ───────────────────────────────────────────────────────────

    def _load(self) -> None:
        if self._path.exists():
            try:
                data = json.loads(self._path.read_text())
                self._queries = [SavedQuery.from_dict(d) for d in data]
            except Exception as exc:
                logger.warning("Failed to load query library: %s", exc)
                self._queries = []

    def _persist(self) -> None:
        try:
            self._path.write_text(
                json.dumps([q.to_dict() for q in self._queries], indent=2)
            )
        except Exception as exc:
            logger.error("Failed to persist query library: %s", exc)
