"""
Natural Language → KQL Generator
Uses OpenAI (or a mock fallback) to convert analyst questions into KQL.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

# System prompt that gives the model Sentinel context
_SYSTEM_PROMPT = """You are an expert Microsoft Sentinel / Azure Log Analytics engineer.
Convert the user's natural language security question into a valid KQL (Kusto Query Language) query.

Rules:
1. Always include a time filter using ago() or between().
2. Use the most appropriate Sentinel tables (SecurityEvent, SigninLogs, AzureActivity,
   CommonSecurityLog, Syslog, DeviceProcessEvents, EmailEvents, IdentityLogonEvents,
   AuditLogs, BehaviorAnalytics, ThreatIntelligenceIndicator, etc.).
3. Limit results to 500 rows by default using `| take 500` or `| limit 500`.
4. Include `| project` to select relevant columns when the output would be too wide.
5. Add descriptive comments with `//` to explain key query steps.
6. Return ONLY the KQL query — no markdown fences, no prose, no explanation.
7. If the question is ambiguous, make the safest reasonable assumption.

Examples:
User: "show me all failed logons for user jdoe in the last 24 hours"
KQL:
SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| where TargetUserName =~ "jdoe"
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName, SubStatus
| order by TimeGenerated desc
| take 500
"""


def generate_kql(
    natural_language: str,
    context: Optional[str] = None,
    max_tokens: int = 800,
) -> dict[str, str]:
    """
    Convert a natural language question to KQL using OpenAI.

    Args:
        natural_language: The analyst's question in plain English.
        context: Optional extra context (e.g., previous query, entity names).
        max_tokens: Maximum tokens in the OpenAI response.

    Returns:
        dict with keys: 'kql' (str), 'source' ('openai' | 'mock').
    """
    settings = get_settings()

    if not settings.openai_api_key:
        logger.warning("OPENAI_API_KEY not set — falling back to mock KQL generator.")
        return {"kql": _mock_kql(natural_language), "source": "mock"}

    try:
        from openai import OpenAI  # lazy import

        client = OpenAI(api_key=settings.openai_api_key)
        messages = [{"role": "system", "content": _SYSTEM_PROMPT}]
        if context:
            messages.append({"role": "user", "content": f"Context: {context}"})
        messages.append({"role": "user", "content": natural_language})

        response = client.chat.completions.create(
            model=settings.openai_model,
            messages=messages,
            max_tokens=max_tokens,
            temperature=0.1,  # Low temperature for deterministic query generation
        )
        kql = response.choices[0].message.content.strip()
        # Strip accidental markdown code fences
        kql = re.sub(r"^```[a-z]*\n?", "", kql, flags=re.IGNORECASE)
        kql = re.sub(r"\n?```$", "", kql)
        return {"kql": kql.strip(), "source": "openai"}

    except Exception as exc:
        logger.error("OpenAI KQL generation failed: %s", exc)
        return {
            "kql": _mock_kql(natural_language),
            "source": "mock",
            "error": str(exc),
        }


def _mock_kql(question: str) -> str:
    """
    Simple keyword-based KQL mock for demo / offline mode.
    Maps common patterns to pre-built queries.
    """
    q = question.lower()

    # Failed logon
    if any(w in q for w in ["failed logon", "failed login", "logon failure", "4625"]):
        user_match = re.search(r"user[:\s]+(\S+)", q)
        user_filter = f'| where TargetUserName =~ "{user_match.group(1)}"' if user_match else ""
        return f"""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
{user_filter}
| project TimeGenerated, Computer, TargetUserName, IpAddress, LogonTypeName, SubStatus
| order by TimeGenerated desc
| take 500"""

    # Sign-in logs
    if any(w in q for w in ["signin", "sign-in", "sign in", "azure ad login"]):
        return """SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress, Location, ResultDescription, RiskLevelAggregated
| order by TimeGenerated desc
| take 500"""

    # Malware / suspicious process
    if any(w in q for w in ["malware", "suspicious process", "malicious", "powershell", "cmd"]):
        return """DeviceProcessEvents
| where Timestamp > ago(24h)
| where FileName in~ ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| where ProcessCommandLine has_any ("Invoke-Expression", "DownloadString", "EncodedCommand", "-enc", "bypass")
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine, InitiatingProcessFileName
| order by Timestamp desc
| take 500"""

    # Phishing
    if any(w in q for w in ["phishing", "email", "malicious url", "suspicious email"]):
        return """EmailEvents
| where Timestamp > ago(7d)
| where ThreatTypes has "Phish"
| project Timestamp, SenderFromAddress, RecipientEmailAddress, Subject, ThreatTypes, DeliveryAction
| order by Timestamp desc
| take 500"""

    # Lateral movement
    if any(w in q for w in ["lateral", "pass the hash", "pth", "wmi", "psexec", "remote"]):
        return """SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4648, 4624)
| where LogonType in (3, 9, 10)
| summarize LogonCount = count() by TargetUserName, IpAddress, Computer
| where LogonCount > 5
| order by LogonCount desc"""

    # Data exfiltration
    if any(w in q for w in ["exfil", "large transfer", "upload", "data transfer", "bytes sent"]):
        return """CommonSecurityLog
| where TimeGenerated > ago(24h)
| where SentBytes > 10000000  // > 10 MB
| project TimeGenerated, SourceIP, DestinationIP, SentBytes, ReceivedBytes, ApplicationProtocol
| order by SentBytes desc
| take 500"""

    # Privilege escalation
    if any(w in q for w in ["privilege", "escalat", "admin", "sudo", "runas", "4672"]):
        return """SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID in (4672, 4673, 4674)
| project TimeGenerated, Computer, SubjectUserName, PrivilegeList
| order by TimeGenerated desc
| take 500"""

    # Generic fallback
    return f"""// Auto-generated query for: {question}
search *
| where TimeGenerated > ago(24h)
| take 100"""
