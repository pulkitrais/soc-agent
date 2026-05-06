"""
Playbook: Privilege Escalation
Investigates attempts to gain higher privileges on Windows and Azure.
"""

from app.playbooks.base import PlaybookBase, PlaybookStep


class PrivilegeEscalationPlaybook(PlaybookBase):
    name = "Privilege Escalation"
    description = (
        "Investigates privilege escalation attempts including UAC bypass, "
        "token manipulation, admin group changes, and Azure role assignments."
    )
    category = "identity"
    mitre_tactic = "Privilege Escalation (TA0004)"

    steps = [
        PlaybookStep(
            title="1. New Privileged Role Assignments (Azure)",
            description="Detect new Global Admin, Owner, or Contributor role assignments.",
            mitre_technique="T1098 – Account Manipulation",
            severity="critical",
            kql="""AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role"
| where Result == "success"
| extend RoleName = tostring(TargetResources[0].displayName),
         AddedUser = tostring(TargetResources[1].userPrincipalName),
         AddedBy = tostring(InitiatedBy.user.userPrincipalName)
| where RoleName in ("Global Administrator", "Privileged Role Administrator",
                     "Security Administrator", "Owner")
| project TimeGenerated, RoleName, AddedUser, AddedBy
| order by TimeGenerated desc""",
        ),
        PlaybookStep(
            title="2. Local Admin Group Modifications",
            description="User added to local Administrators or Backup Operators group.",
            mitre_technique="T1098 – Account Manipulation",
            severity="high",
            kql="""SecurityEvent
| where TimeGenerated > ago(7d)
| where EventID in (4732, 4728, 4756)
| where TargetUserName in~ ("Administrators", "Domain Admins", "Backup Operators",
                             "Remote Desktop Users")
| project TimeGenerated, Computer, SubjectUserName, MemberName, TargetUserName
| order by TimeGenerated desc""",
        ),
        PlaybookStep(
            title="3. Token Impersonation",
            description="Detect use of sensitive privileges commonly used for token stealing.",
            mitre_technique="T1134 – Access Token Manipulation",
            severity="high",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4672
| where PrivilegeList has_any ("SeDebugPrivilege", "SeTcbPrivilege",
                                "SeAssignPrimaryTokenPrivilege")
| project TimeGenerated, Computer, SubjectUserName, SubjectLogonId, PrivilegeList
| order by TimeGenerated desc
| take 200""",
        ),
        PlaybookStep(
            title="4. UAC Bypass Indicators",
            description="Detect common UAC bypass techniques via auto-elevated binaries.",
            mitre_technique="T1548.002 – Bypass User Account Control",
            severity="high",
            kql="""DeviceProcessEvents
| where Timestamp > ago(24h)
| where ProcessIntegrityLevel == "High"
| where InitiatingProcessIntegrityLevel == "Medium"
| where FileName in~ (
    "eventvwr.exe", "fodhelper.exe", "sdclt.exe", "cmstp.exe",
    "computerdefaults.exe", "mmc.exe"
  )
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
| take 200""",
        ),
        PlaybookStep(
            title="5. Service Account Abuse",
            description="Detect logons using known service accounts outside expected hosts.",
            mitre_technique="T1078.003 – Local Accounts",
            severity="high",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where TargetUserName endswith "$" or TargetUserName startswith "svc-"
| summarize LogonCount = count(), Machines = make_set(Computer)
  by TargetUserName, IpAddress
| where array_length(Machines) > 3
| order by LogonCount desc""",
        ),
    ]
