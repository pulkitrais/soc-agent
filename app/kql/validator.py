"""
KQL Query Validator
Performs static analysis on KQL strings before execution.
Checks for missing time filters, dangerous patterns, and syntax issues.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ValidationResult:
    """Result of KQL static analysis."""

    is_valid: bool = True
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        self.is_valid = False

    def add_warning(self, msg: str) -> None:
        self.warnings.append(msg)

    def add_suggestion(self, msg: str) -> None:
        self.suggestions.append(msg)


# Tables that are known to be high-volume in Sentinel deployments
HIGH_VOLUME_TABLES = {
    "securityevent",
    "commonsecuritylog",
    "syslog",
    "signinlogs",
    "azureactivity",
    "officeactivity",
    "azurediagnostics",
}

# Dangerous / risky KQL operations
DANGEROUS_PATTERNS = [
    (r"\bexternaldata\b", "externaldata() can load arbitrary external data — review carefully"),
    (r"\bhttp_request\b", "http_request plugin makes outbound requests — verify intent"),
    (r"drop\s+table", "DROP TABLE detected — this modifies stored data"),
]

# Sentinel table names for basic validation
KNOWN_TABLES = {
    "securityevent", "signinlogs", "azureactivity", "commonsecuritylog",
    "syslog", "deviceprocessevents", "emailevents", "identitylogonevents",
    "auditlogs", "behavioranalytics", "threatintelligenceindicator",
    "securityalert", "securityincident", "sentinelhealth",
    "azuread", "officeactivity", "microsoftgraphactivitylogs",
    "windowsevent", "linuxauditlog", "dfirtracked", "watchlist",
    "networksessions", "azurefirewall", "dnsnormalized",
}


def validate_kql(kql: str) -> ValidationResult:
    """
    Statically validate a KQL query.

    Args:
        kql: The KQL query string to validate.

    Returns:
        ValidationResult with errors, warnings, and suggestions.
    """
    result = ValidationResult()
    kql_stripped = kql.strip()

    # ── Basic checks ──────────────────────────────────────────────────────────

    if not kql_stripped:
        result.add_error("Query is empty.")
        return result

    kql_lower = kql_stripped.lower()

    # ── Time filter ───────────────────────────────────────────────────────────

    has_time_filter = (
        "ago(" in kql_lower
        or "between(" in kql_lower
        or "timegenerated" in kql_lower
        or "timestamp" in kql_lower
        or "starttime" in kql_lower
    )
    if not has_time_filter:
        result.add_warning(
            "No time filter detected. This may scan ALL data and be very expensive."
        )
        result.add_suggestion("Add `| where TimeGenerated > ago(24h)` to limit the scan.")

    # ── Row limit ─────────────────────────────────────────────────────────────

    has_row_limit = any(
        kw in kql_lower for kw in ["| take ", "| limit ", "|take ", "|limit "]
    )
    if not has_row_limit:
        result.add_suggestion(
            "Consider adding `| take 500` to limit result set size."
        )

    # ── High-volume table warning ─────────────────────────────────────────────

    for table in HIGH_VOLUME_TABLES:
        pattern = rf"\b{table}\b"
        if re.search(pattern, kql_lower):
            result.add_warning(
                f"Table '{table}' is typically high-volume. Ensure a tight time filter is in place."
            )

    # ── Dangerous operations ──────────────────────────────────────────────────

    for pattern, message in DANGEROUS_PATTERNS:
        if re.search(pattern, kql_lower, re.IGNORECASE):
            result.add_error(f"Potentially dangerous operation detected: {message}")

    # ── Injection / special character check ──────────────────────────────────
    # KQL is read-only for Log Analytics so injection risk is low, but we check
    # for template injection patterns that might indicate bad user input.

    suspicious_chars = re.findall(r"[;\x00-\x08\x0b\x0c\x0e-\x1f]", kql_stripped)
    if suspicious_chars:
        result.add_warning(
            "Query contains unusual control characters — please review before execution."
        )

    # ── Syntax hints ─────────────────────────────────────────────────────────

    # Unmatched parentheses / brackets
    if kql_stripped.count("(") != kql_stripped.count(")"):
        result.add_error("Unmatched parentheses detected in query.")

    if kql_stripped.count("[") != kql_stripped.count("]"):
        result.add_error("Unmatched square brackets detected in query.")

    return result
