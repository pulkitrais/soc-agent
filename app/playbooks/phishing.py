"""
Playbook: Phishing / Email Investigation
Investigates email-based threats and follow-on activity.
"""

from app.playbooks.base import PlaybookBase, PlaybookStep


class PhishingPlaybook(PlaybookBase):
    name = "Phishing / Email Investigation"
    description = (
        "Investigates phishing emails, malicious URLs in messages, "
        "and post-delivery user interaction indicators."
    )
    category = "email"
    mitre_tactic = "Initial Access (TA0001) – T1566"

    steps = [
        PlaybookStep(
            title="1. Phishing Emails Delivered",
            description="Find emails flagged as phishing that were delivered.",
            mitre_technique="T1566.002 – Spear Phishing Link",
            severity="high",
            kql="""EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| where DeliveryAction == "Delivered"
| project Timestamp, SenderFromAddress, SenderIPv4, RecipientEmailAddress,
          Subject, ThreatTypes, UrlCount, AttachmentCount, EmailClusterId
| order by Timestamp desc
| take 200""",
        ),
        PlaybookStep(
            title="2. Malicious URLs in Emails",
            description="Extract malicious or suspicious URLs from email threat data.",
            mitre_technique="T1566.002 – Spear Phishing Link",
            severity="high",
            kql="""EmailUrlInfo
| where Timestamp > ago(7d)
| join kind=inner (
    EmailEvents
    | where ThreatTypes has "Phish"
    | project NetworkMessageId, RecipientEmailAddress
  ) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, Url, UrlDomain, ThreatTypes
| order by Timestamp desc
| take 300""",
        ),
        PlaybookStep(
            title="3. Malicious Attachments",
            description="Identify emails with malicious attachments that were opened.",
            mitre_technique="T1566.001 – Spear Phishing Attachment",
            severity="critical",
            kql="""EmailAttachmentInfo
| where Timestamp > ago(7d)
| where ThreatTypes has_any ("Malware", "Phish")
| project Timestamp, FileName, FileType, SHA256, ThreatTypes, MalwareFamily, NetworkMessageId
| order by Timestamp desc
| take 200""",
        ),
        PlaybookStep(
            title="4. Users Who Clicked Phishing Links",
            description="Correlate email delivery with URL click events.",
            mitre_technique="T1204.001 – Malicious Link",
            severity="critical",
            kql="""UrlClickEvents
| where Timestamp > ago(7d)
| where IsClickedThrough == 1
| where ThreatTypes has_any ("Phish", "Malware")
| project Timestamp, AccountUpn, Url, UrlDomain, ActionType, IPAddress, ThreatTypes
| order by Timestamp desc
| take 200""",
        ),
        PlaybookStep(
            title="5. Post-Phishing Sign-in Activity",
            description="Check for suspicious sign-ins shortly after phishing delivery.",
            mitre_technique="T1078 – Valid Accounts (post-compromise)",
            severity="high",
            kql="""SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelDuringSignIn in ("medium", "high")
| project TimeGenerated, UserPrincipalName, IPAddress, Location,
          AppDisplayName, RiskDetail, ResultType
| order by TimeGenerated desc
| take 200""",
        ),
        PlaybookStep(
            title="6. Email Rule Manipulation (Inbox Rules)",
            description="Detect attacker-created inbox rules to hide or forward emails.",
            mitre_technique="T1564.008 – Email Hiding Rules",
            severity="high",
            kql="""OfficeActivity
| where TimeGenerated > ago(7d)
| where Operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
| project TimeGenerated, UserId, ClientIP, Parameters
| order by TimeGenerated desc""",
        ),
    ]
