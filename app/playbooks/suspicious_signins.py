"""
Playbook: Suspicious Sign-ins
Investigates anomalous or risky Azure AD / hybrid authentication events.
"""

from app.playbooks.base import PlaybookBase, PlaybookStep


class SuspiciousSigninsPlaybook(PlaybookBase):
    name = "Suspicious Sign-ins"
    description = (
        "Investigates risky, impossible-travel, and anomalous Azure AD sign-in events. "
        "Covers brute-force, password spray, and token theft indicators."
    )
    category = "identity"
    mitre_tactic = "Initial Access (TA0001)"

    steps = [
        PlaybookStep(
            title="1. Risky Sign-ins Overview",
            description="Pull all medium/high risk sign-ins in the last 7 days.",
            mitre_technique="T1078 – Valid Accounts",
            severity="high",
            kql="""SigninLogs
| where TimeGenerated > ago(7d)
| where RiskLevelAggregated in ("medium", "high")
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          Location, RiskDetail, RiskLevelAggregated, ConditionalAccessStatus
| order by TimeGenerated desc
| take 200""",
        ),
        PlaybookStep(
            title="2. Failed Logon Summary (AD)",
            description="Identify accounts with high failed-logon counts — potential brute-force.",
            mitre_technique="T1110 – Brute Force",
            severity="high",
            kql="""SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| summarize FailureCount = count(),
            UniqueIPs = dcount(IpAddress),
            FirstSeen = min(TimeGenerated),
            LastSeen = max(TimeGenerated)
  by TargetUserName
| where FailureCount > 10
| order by FailureCount desc""",
        ),
        PlaybookStep(
            title="3. Impossible Travel Detection",
            description="Find users signing in from geographically distant locations within a short timeframe.",
            mitre_technique="T1078 – Valid Accounts",
            severity="critical",
            kql="""SigninLogs
| where TimeGenerated > ago(7d)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress,
          City = tostring(LocationDetails.city),
          Country = tostring(LocationDetails.countryOrRegion)
| partition by UserPrincipalName (
    order by TimeGenerated asc
    | extend PrevCountry = prev(Country), PrevTime = prev(TimeGenerated)
    | where PrevCountry != Country and datetime_diff("hour", TimeGenerated, PrevTime) < 4
    | project TimeGenerated, UserPrincipalName, Country, PrevCountry, IPAddress
)
| order by TimeGenerated desc
| take 100""",
        ),
        PlaybookStep(
            title="4. Password Spray Detection",
            description="Look for a single IP attempting many different user accounts.",
            mitre_technique="T1110.003 – Password Spraying",
            severity="high",
            kql="""SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType != 0
| summarize UniqueUsers = dcount(UserPrincipalName),
            Attempts = count(),
            UserList = make_set(UserPrincipalName, 20)
  by IPAddress
| where UniqueUsers > 5
| order by UniqueUsers desc""",
        ),
        PlaybookStep(
            title="5. MFA Fatigue / Push Spam",
            description="Detect accounts receiving many MFA prompts in a short window.",
            mitre_technique="T1621 – Multi-Factor Authentication Request Generation",
            severity="high",
            kql="""SigninLogs
| where TimeGenerated > ago(24h)
| where AuthenticationRequirement == "multiFactorAuthentication"
| where ResultType in ("50074", "50076", "500121")  // MFA-related result codes
| summarize MFAAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where MFAAttempts > 5
| order by MFAAttempts desc""",
        ),
        PlaybookStep(
            title="6. Conditional Access Policy Failures",
            description="Sign-ins blocked or interrupted by Conditional Access.",
            mitre_technique="T1078 – Valid Accounts",
            severity="medium",
            kql="""SigninLogs
| where TimeGenerated > ago(7d)
| where ConditionalAccessStatus == "failure"
| project TimeGenerated, UserPrincipalName, AppDisplayName, IPAddress,
          Location, ConditionalAccessPolicies
| order by TimeGenerated desc
| take 200""",
        ),
    ]
