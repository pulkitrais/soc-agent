"""
Playbook: Command & Control (C2)
Investigates C2 communication patterns.
"""

from app.playbooks.base import PlaybookBase, PlaybookStep


class C2Playbook(PlaybookBase):
    name = "Command & Control"
    description = (
        "Investigates indicators of C2 communication including beaconing, "
        "DNS tunnelling, unusual outbound connections, and known C2 frameworks."
    )
    category = "network"
    mitre_tactic = "Command and Control (TA0011)"

    steps = [
        PlaybookStep(
            title="1. Network Beaconing Detection",
            description="Identify hosts communicating with an external IP at regular intervals.",
            mitre_technique="T1071 – Application Layer Protocol",
            severity="high",
            kql="""NetworkSessions
| where TimeGenerated > ago(24h)
| where isnotempty(DestinationIp)
| summarize ConnectionCount = count(),
            BytesSent = sum(SentBytes),
            TimeDiffs = make_list(TimeGenerated, 100)
  by DeviceName, DestinationIp, DestinationPort
| where ConnectionCount > 20
| extend AvgBytesSent = BytesSent / ConnectionCount
| where AvgBytesSent < 5000  // Small consistent payloads typical of beacons
| order by ConnectionCount desc
| take 100""",
        ),
        PlaybookStep(
            title="2. DNS Tunnelling Indicators",
            description="High-entropy domain names or excessive DNS query volume.",
            mitre_technique="T1071.004 – DNS",
            severity="high",
            kql="""DnsEvents
| where TimeGenerated > ago(24h)
| summarize QueryCount = count(), DomainLength = max(strlen(Name))
  by ClientIP, Name
| where DomainLength > 50 or QueryCount > 100
| order by QueryCount desc
| take 200""",
        ),
        PlaybookStep(
            title="3. Connections to Threat Intel IPs",
            description="Cross-reference outbound connections against threat intelligence.",
            mitre_technique="T1071 – Application Layer Protocol",
            severity="critical",
            kql="""NetworkSessions
| where TimeGenerated > ago(24h)
| join kind=inner (
    ThreatIntelligenceIndicator
    | where TimeGenerated > ago(30d)
    | where Active == true
    | where isnotempty(NetworkIP)
    | project ThreatIP = NetworkIP, ThreatType, ConfidenceScore
  ) on $left.DestinationIp == $right.ThreatIP
| project TimeGenerated, DeviceName, DestinationIp, DestinationPort,
          ThreatType, ConfidenceScore
| order by ConfidenceScore desc, TimeGenerated desc
| take 200""",
        ),
        PlaybookStep(
            title="4. Non-Standard Port Outbound",
            description="Connections on uncommon ports that may indicate C2 or data exfil.",
            mitre_technique="T1571 – Non-Standard Port",
            severity="medium",
            kql="""NetworkSessions
| where TimeGenerated > ago(24h)
| where DestinationPort !in (80, 443, 53, 8080, 8443, 22, 25, 587, 143, 993)
| where DestinationIp !startswith "10."
    and DestinationIp !startswith "192.168."
    and DestinationIp !startswith "172."
| summarize Connections = count() by DeviceName, DestinationIp, DestinationPort
| where Connections > 5
| order by Connections desc""",
        ),
        PlaybookStep(
            title="5. Common C2 Framework Indicators",
            description="Detect process/network patterns associated with Cobalt Strike, Meterpreter, etc.",
            mitre_technique="T1059 – Command and Scripting Interpreter",
            severity="critical",
            kql="""DeviceNetworkEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ ("powershell.exe", "rundll32.exe", "svchost.exe")
| where RemotePort in (4444, 4445, 8888, 9999, 50050, 60000)
| project Timestamp, DeviceName, InitiatingProcessFileName,
          RemoteIP, RemotePort, LocalPort
| order by Timestamp desc
| take 200""",
        ),
    ]
