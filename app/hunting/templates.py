"""
MITRE ATT&CK Threat Hunting Templates
Pre-built hunting queries mapped to ATT&CK tactics and techniques.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class HuntingTemplate:
    """A single threat hunting query template."""

    id: str
    name: str
    description: str
    kql: str
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_id: str
    data_sources: list[str] = field(default_factory=list)
    severity: str = "medium"  # low | medium | high | critical
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "kql": self.kql,
            "mitre_tactic": self.mitre_tactic,
            "mitre_technique": self.mitre_technique,
            "mitre_technique_id": self.mitre_technique_id,
            "data_sources": self.data_sources,
            "severity": self.severity,
            "tags": self.tags,
        }


HUNTING_TEMPLATES: list[HuntingTemplate] = [
    # ── Reconnaissance ────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-001",
        name="Account Enumeration via LDAP",
        description="Hunt for bulk LDAP queries that may indicate AD reconnaissance.",
        mitre_tactic="Reconnaissance (TA0043)",
        mitre_technique="Account Discovery",
        mitre_technique_id="T1087",
        data_sources=["SecurityEvent"],
        severity="medium",
        tags=["reconnaissance", "active-directory"],
        kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4662
| where Properties has "1.2.840.113556.1.4.803"  // LDAP query
| summarize LDAPQueries = count() by SubjectUserName, Computer
| where LDAPQueries > 100
| order by LDAPQueries desc""",
    ),

    # ── Initial Access ────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-002",
        name="External IP Sign-in to Admin Accounts",
        description="Hunt for privileged accounts signing in from unusual external IPs.",
        mitre_tactic="Initial Access (TA0001)",
        mitre_technique="Valid Accounts",
        mitre_technique_id="T1078",
        data_sources=["SigninLogs", "AuditLogs"],
        severity="high",
        tags=["initial-access", "identity", "privileged-account"],
        kql="""SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| where IPAddress !startswith "10." and IPAddress !startswith "192.168."
| join kind=inner (
    AuditLogs
    | where OperationName == "Add member to role"
    | extend PrivUser = tostring(TargetResources[1].userPrincipalName)
    | project PrivUser
  ) on $left.UserPrincipalName == $right.PrivUser
| project TimeGenerated, UserPrincipalName, IPAddress, Location, AppDisplayName
| order by TimeGenerated desc""",
    ),

    # ── Execution ─────────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-003",
        name="LSASS Memory Dump",
        description="Hunt for attempts to dump LSASS credentials.",
        mitre_tactic="Credential Access (TA0006)",
        mitre_technique="OS Credential Dumping: LSASS Memory",
        mitre_technique_id="T1003.001",
        data_sources=["DeviceProcessEvents"],
        severity="critical",
        tags=["credential-access", "lsass", "mimikatz"],
        kql="""DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName =~ "procdump.exe" or ProcessCommandLine has "lsass"
    or (FileName =~ "rundll32.exe" and ProcessCommandLine has "comsvcs.dll")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc""",
    ),

    HuntingTemplate(
        id="hunt-004",
        name="Windows Credential Access via Registry",
        description="Hunt for SAM database and credential registry reads.",
        mitre_tactic="Credential Access (TA0006)",
        mitre_technique="OS Credential Dumping: Security Account Manager",
        mitre_technique_id="T1003.002",
        data_sources=["DeviceRegistryEvents"],
        severity="critical",
        tags=["credential-access", "sam", "registry"],
        kql="""DeviceRegistryEvents
| where Timestamp > ago(24h)
| where RegistryKey has_any (
    "HKLM\\SAM\\SAM\\Domains\\Account\\Users",
    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\",
    "HKLM\\SECURITY\\Policy\\Secrets"
  )
| project Timestamp, DeviceName, AccountName, ActionType, RegistryKey, InitiatingProcessFileName
| order by Timestamp desc
| take 200""",
    ),

    # ── Persistence ───────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-005",
        name="Scheduled Task Creation",
        description="Hunt for new or modified scheduled tasks — common persistence mechanism.",
        mitre_tactic="Persistence (TA0003)",
        mitre_technique="Scheduled Task/Job",
        mitre_technique_id="T1053.005",
        data_sources=["SecurityEvent", "DeviceEvents"],
        severity="medium",
        tags=["persistence", "scheduled-task"],
        kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4698  // A scheduled task was created
| project TimeGenerated, Computer, SubjectUserName,
          TaskName = extract("Task Name:\\s+(.+?)\\r", 1, EventData),
          TaskContent = extract("Task Content:\\s+(.+)", 1, EventData)
| order by TimeGenerated desc""",
    ),

    HuntingTemplate(
        id="hunt-006",
        name="Registry Run Key Persistence",
        description="Hunt for new values written to autorun registry keys.",
        mitre_tactic="Persistence (TA0003)",
        mitre_technique="Boot or Logon Autostart Execution: Registry Run Keys",
        mitre_technique_id="T1547.001",
        data_sources=["DeviceRegistryEvents"],
        severity="high",
        tags=["persistence", "registry", "autorun"],
        kql="""DeviceRegistryEvents
| where Timestamp > ago(24h)
| where ActionType == "RegistryValueSet"
| where RegistryKey has_any (
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\Run",
    "\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
    "\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"
  )
| project Timestamp, DeviceName, AccountName, RegistryKey,
          RegistryValueName, RegistryValueData, InitiatingProcessFileName
| order by Timestamp desc""",
    ),

    # ── Defence Evasion ───────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-007",
        name="Audit Log Clearing",
        description="Hunt for attempts to clear Windows event logs.",
        mitre_tactic="Defence Evasion (TA0005)",
        mitre_technique="Indicator Removal: Clear Windows Event Logs",
        mitre_technique_id="T1070.001",
        data_sources=["SecurityEvent"],
        severity="critical",
        tags=["defence-evasion", "log-clearing"],
        kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (1102, 104)  // Security log cleared / System log cleared
| project TimeGenerated, Computer, SubjectUserName, Activity
| order by TimeGenerated desc""",
    ),

    # ── Discovery ─────────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-008",
        name="Network Port Scanning",
        description="Hunt for rapid sequential port connections indicating scanning.",
        mitre_tactic="Discovery (TA0007)",
        mitre_technique="Network Service Discovery",
        mitre_technique_id="T1046",
        data_sources=["DeviceNetworkEvents"],
        severity="medium",
        tags=["discovery", "scanning"],
        kql="""DeviceNetworkEvents
| where Timestamp > ago(1h)
| where ActionType == "ConnectionFailed"
| summarize PortsAttempted = dcount(RemotePort), IPs = dcount(RemoteIP)
  by DeviceName, InitiatingProcessFileName, bin(Timestamp, 10m)
| where PortsAttempted > 20 or IPs > 10
| order by PortsAttempted desc""",
    ),

    # ── Collection ────────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-009",
        name="Clipboard Data Access",
        description="Hunt for processes accessing clipboard content — data collection.",
        mitre_tactic="Collection (TA0009)",
        mitre_technique="Clipboard Data",
        mitre_technique_id="T1115",
        data_sources=["DeviceEvents"],
        severity="medium",
        tags=["collection", "clipboard"],
        kql="""DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "GetClipboardData"
| project Timestamp, DeviceName, AccountName, InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
| take 100""",
    ),

    # ── Exfiltration ─────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-010",
        name="Anomalous SharePoint Access",
        description="Hunt for users accessing an unusually high number of SharePoint documents.",
        mitre_tactic="Collection / Exfiltration",
        mitre_technique="Data from Cloud Storage",
        mitre_technique_id="T1530",
        data_sources=["OfficeActivity"],
        severity="high",
        tags=["exfiltration", "sharepoint", "cloud-storage"],
        kql="""OfficeActivity
| where TimeGenerated > ago(24h)
| where RecordType == "SharePointFileOperation"
| where Operation in ("FileDownloaded", "FileCopied", "FileSyncDownloadedFull")
| summarize FileCount = count() by UserId, ClientIP, bin(TimeGenerated, 1h)
| where FileCount > 100
| order by FileCount desc""",
    ),

    # ── Impact ────────────────────────────────────────────────────────────────
    HuntingTemplate(
        id="hunt-011",
        name="Ransomware File Extension Pattern",
        description="Hunt for mass file renames/changes with unusual extensions.",
        mitre_tactic="Impact (TA0040)",
        mitre_technique="Data Encrypted for Impact",
        mitre_technique_id="T1486",
        data_sources=["DeviceFileEvents"],
        severity="critical",
        tags=["impact", "ransomware"],
        kql=r"""DeviceFileEvents
| where Timestamp > ago(1h)
| where ActionType in ("FileRenamed", "FileCreated")
| where FileName matches regex @"\.(locked|encrypted|enc|crypt|[a-z0-9]{5,10})$"
| summarize FileCount = count() by DeviceName, AccountName, bin(Timestamp, 5m)
| where FileCount > 50
| order by FileCount desc""",
    ),
]


def get_templates_by_tactic(tactic: str) -> list[HuntingTemplate]:
    """Filter hunting templates by MITRE tactic name."""
    tactic_lower = tactic.lower()
    return [t for t in HUNTING_TEMPLATES if tactic_lower in t.mitre_tactic.lower()]


def get_template_by_id(template_id: str) -> HuntingTemplate | None:
    """Retrieve a single template by its ID."""
    return next((t for t in HUNTING_TEMPLATES if t.id == template_id), None)


def get_all_tactics() -> list[str]:
    """Return distinct list of MITRE tactics covered."""
    return sorted({t.mitre_tactic for t in HUNTING_TEMPLATES})
