"""
Playbook: Data Exfiltration
Investigates large data transfers, cloud storage abuse, and email-based exfiltration.
"""

from app.playbooks.base import PlaybookBase, PlaybookStep


class DataExfiltrationPlaybook(PlaybookBase):
    name = "Data Exfiltration"
    description = (
        "Investigates large or suspicious data transfers out of the organisation, "
        "including cloud storage uploads, email exfil, and network-based transfers."
    )
    category = "data"
    mitre_tactic = "Exfiltration (TA0010)"

    steps = [
        PlaybookStep(
            title="1. Large Outbound Network Transfers",
            description="Detect hosts sending unusually large volumes of data externally.",
            mitre_technique="T1048 – Exfiltration Over Alternative Protocol",
            severity="high",
            kql="""CommonSecurityLog
| where TimeGenerated > ago(24h)
| where SentBytes > 10000000  // > 10 MB per session
| where DestinationIP !startswith "10."
    and DestinationIP !startswith "192.168."
    and DestinationIP !startswith "172."
| project TimeGenerated, SourceIP, DestinationIP, SentBytes, ReceivedBytes,
          ApplicationProtocol, DestinationPort
| order by SentBytes desc
| take 200""",
        ),
        PlaybookStep(
            title="2. SharePoint / OneDrive Mass Download",
            description="Detect bulk file downloads from SharePoint or OneDrive.",
            mitre_technique="T1213 – Data from Information Repositories",
            severity="high",
            kql="""OfficeActivity
| where TimeGenerated > ago(24h)
| where Operation in ("FileDownloaded", "FileAccessed")
| summarize DownloadCount = count(), FilePaths = make_set(OfficeObjectId, 20)
  by UserId, ClientIP, bin(TimeGenerated, 1h)
| where DownloadCount > 50
| order by DownloadCount desc""",
        ),
        PlaybookStep(
            title="3. Email Exfiltration",
            description="Large attachments or bulk forwarding of emails externally.",
            mitre_technique="T1048.003 – Exfiltration Over Unencrypted/Obfuscated Non-C2 Protocol",
            severity="high",
            kql="""EmailEvents
| where Timestamp > ago(7d)
| where SenderFromDomain != ""  // Outbound
| summarize EmailsSent = count(), AvgAttachments = avg(AttachmentCount)
  by SenderFromAddress, RecipientEmailAddress
| where EmailsSent > 20 or AvgAttachments > 3
| order by EmailsSent desc
| take 200""",
        ),
        PlaybookStep(
            title="4. Cloud Storage Uploads (Azure Blob)",
            description="Detect data uploads to Azure Blob Storage.",
            mitre_technique="T1567.002 – Exfiltration to Cloud Storage",
            severity="high",
            kql="""StorageBlobLogs
| where TimeGenerated > ago(24h)
| where OperationName == "PutBlob"
| summarize UploadCount = count(), TotalBytes = sum(RequestBodySize)
  by CallerIpAddress, AccountName, bin(TimeGenerated, 1h)
| where TotalBytes > 5000000  // > 5 MB
| order by TotalBytes desc""",
        ),
        PlaybookStep(
            title="5. Data Staging (Compression / Archive Creation)",
            description="Detect use of compression tools that may indicate staging before exfil.",
            mitre_technique="T1560 – Archive Collected Data",
            severity="medium",
            kql="""DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("7z.exe", "winrar.exe", "rar.exe", "zip.exe", "tar.exe")
    or ProcessCommandLine has_any ("-p", "--password", "-pw")  // Password-protected archives
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
| order by Timestamp desc
| take 200""",
        ),
        PlaybookStep(
            title="6. USB / Removable Media Activity",
            description="Detect files written to removable drives.",
            mitre_technique="T1052 – Exfiltration over Physical Medium",
            severity="high",
            kql="""DeviceEvents
| where Timestamp > ago(24h)
| where ActionType == "UsbDriveMounted"
| project Timestamp, DeviceName, AccountName, AdditionalFields
| order by Timestamp desc
| take 200""",
        ),
    ]
