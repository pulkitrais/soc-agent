"""
Base Playbook Class
All investigation playbooks inherit from PlaybookBase.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class PlaybookStep:
    """A single step in an investigation playbook."""

    title: str
    description: str
    kql: str
    mitre_technique: str = ""
    expected_output: str = ""
    severity: str = "medium"  # low | medium | high | critical


@dataclass
class PlaybookResult:
    """Holds the outcome of running a playbook."""

    playbook_name: str
    steps_run: int = 0
    findings: list[dict[str, Any]] = field(default_factory=list)
    risk_score: int = 0  # 0-100
    risk_level: str = "unknown"
    summary: str = ""


class PlaybookBase:
    """
    Abstract base for investigation playbooks.
    Each playbook defines a series of KQL-based investigation steps.
    """

    name: str = "Base Playbook"
    description: str = ""
    category: str = "general"
    mitre_tactic: str = ""
    steps: list[PlaybookStep] = []

    # ── Public API ────────────────────────────────────────────────────────────

    def get_steps(self) -> list[PlaybookStep]:
        return list(self.steps)

    def get_step_kql(self, step_index: int, **substitutions) -> str:
        """Return the KQL for a step, substituting template variables."""
        step = self.steps[step_index]
        kql = step.kql
        for key, value in substitutions.items():
            # Sanitise: only allow alphanumeric, @, ., -, _ in substitution values
            safe_value = _sanitise_substitution(value)
            kql = kql.replace(f"{{{{{key}}}}}", safe_value)
        return kql

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "description": self.description,
            "category": self.category,
            "mitre_tactic": self.mitre_tactic,
            "steps": [
                {
                    "title": s.title,
                    "description": s.description,
                    "kql": s.kql,
                    "mitre_technique": s.mitre_technique,
                    "severity": s.severity,
                }
                for s in self.steps
            ],
        }


def _sanitise_substitution(value: str) -> str:
    """
    Sanitise a string value before substituting into a KQL template.
    Strips characters that could break KQL syntax or inject commands.
    Only permits: alphanumeric, @, ., -, _, space, @, #, +
    """
    import re
    # Allow characters commonly found in usernames, IPs, and hostnames
    return re.sub(r"[^\w@.\-\s#+]", "", str(value))
