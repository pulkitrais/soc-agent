"""
Playbook: Lateral Movement
Investigates internal movement between systems using stolen credentials.
"""

from app.playbooks.base import PlaybookBase, PlaybookStep


class LateralMovementPlaybook(PlaybookBase):
    name = "Lateral Movement"
    description = (
        "Investigates attacker movement through the network after initial access, "
        "including pass-the-hash, pass-the-ticket, RDP, WMI, and SMB lateral movement."
    )
    category = "network"
    mitre_tactic = "Lateral Movement (TA0008)"

    steps = [
        PlaybookStep(
            title="1. Pass-the-Hash Detection",
            description="Look for NTLM network logons with explicit credentials — PtH indicator.",
            mitre_technique="T1550.002 – Pass the Hash",
            severity="critical",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 3  // Network logon
| where AuthenticationPackageName == "NTLM"
| summarize NTLMLogons = count(), TargetHosts = make_set(Computer)
  by SubjectUserName, IpAddress
| where NTLMLogons > 3
| order by NTLMLogons desc""",
        ),
        PlaybookStep(
            title="2. RDP Lateral Movement",
            description="Detect RDP logon events (type 10) across multiple machines.",
            mitre_technique="T1021.001 – Remote Desktop Protocol",
            severity="high",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType == 10
| summarize RDPSessions = count(),
            TargetMachines = make_set(Computer),
            TargetCount = dcount(Computer)
  by TargetUserName, IpAddress
| where TargetCount > 1
| order by TargetCount desc""",
        ),
        PlaybookStep(
            title="3. WMI Remote Execution",
            description="Detect WMI-based remote command execution.",
            mitre_technique="T1047 – Windows Management Instrumentation",
            severity="high",
            kql="""DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName =~ "WmiPrvSE.exe"
| where FileName in~ ("cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe")
| project Timestamp, DeviceName, AccountName, FileName,
          ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp desc
| take 200""",
        ),
        PlaybookStep(
            title="4. PsExec / SMB Admin Share Activity",
            description="Detect use of PsExec or remote admin share connections.",
            mitre_technique="T1570 – Lateral Tool Transfer",
            severity="high",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 5145
| where ShareName in ("ADMIN$", "C$", "IPC$")
| summarize AccessCount = count(), UniqueIPs = dcount(IpAddress)
  by Computer, SubjectUserName, ShareName
| where AccessCount > 3
| order by AccessCount desc""",
        ),
        PlaybookStep(
            title="5. Kerberoasting Detection",
            description="Look for excessive Kerberos TGS requests — Kerberoasting indicator.",
            mitre_technique="T1558.003 – Kerberoasting",
            severity="high",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4769
| where TicketEncryptionType == "0x17"  // RC4 — older, more crackable
| summarize TGSCount = count() by SubjectUserName, ServiceName, IpAddress
| where TGSCount > 10
| order by TGSCount desc""",
        ),
        PlaybookStep(
            title="6. Cross-Machine Logon Timeline",
            description="Build a timeline of a specific account's logon activity across machines.",
            mitre_technique="T1021 – Remote Services",
            severity="medium",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4624
| where LogonType in (3, 9, 10)
| summarize LogonCount = count(),
            Machines = make_set(Computer),
            MachineCount = dcount(Computer)
  by TargetUserName
| where MachineCount > 5
| order by MachineCount desc""",
        ),
    ]
