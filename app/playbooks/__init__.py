"""
Playbook Registry
Central registry for all available playbooks.
"""

from __future__ import annotations

from app.playbooks.base import PlaybookBase
from app.playbooks.suspicious_signins import SuspiciousSigninsPlaybook
from app.playbooks.malware import MalwarePlaybook
from app.playbooks.phishing import PhishingPlaybook
from app.playbooks.lateral_movement import LateralMovementPlaybook
from app.playbooks.c2 import C2Playbook
from app.playbooks.privilege_escalation import PrivilegeEscalationPlaybook
from app.playbooks.data_exfiltration import DataExfiltrationPlaybook

# Ordered list of all playbooks
ALL_PLAYBOOKS: list[type[PlaybookBase]] = [
    SuspiciousSigninsPlaybook,
    MalwarePlaybook,
    PhishingPlaybook,
    LateralMovementPlaybook,
    C2Playbook,
    PrivilegeEscalationPlaybook,
    DataExfiltrationPlaybook,
]

PLAYBOOK_REGISTRY: dict[str, type[PlaybookBase]] = {
    pb.name: pb for pb in ALL_PLAYBOOKS
}


def get_playbook(name: str) -> PlaybookBase:
    """Instantiate and return a playbook by name."""
    cls = PLAYBOOK_REGISTRY.get(name)
    if cls is None:
        raise KeyError(f"Unknown playbook: {name!r}. Available: {list(PLAYBOOK_REGISTRY)}")
    return cls()
