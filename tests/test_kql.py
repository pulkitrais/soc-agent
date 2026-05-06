"""
Tests for KQL generator (mock fallback path — no OpenAI key required).
"""

from __future__ import annotations

import pytest

from app.kql.generator import generate_kql, _mock_kql
from app.kql.validator import validate_kql


class TestMockKqlGenerator:
    """Tests for the keyword-based mock KQL generator."""

    def test_failed_logon_query(self):
        result = generate_kql("show failed logons in the last 24 hours")
        assert result["kql"]
        assert "SecurityEvent" in result["kql"]
        assert "4625" in result["kql"]

    def test_signin_query(self):
        result = generate_kql("show all risky sign-in events")
        assert result["kql"]
        assert "SigninLogs" in result["kql"]

    def test_malware_query(self):
        result = generate_kql("suspicious powershell execution today")
        assert result["kql"]
        assert "powershell" in result["kql"].lower()

    def test_phishing_query(self):
        result = generate_kql("phishing email delivered to users")
        assert result["kql"]
        assert "EmailEvents" in result["kql"]

    def test_lateral_movement_query(self):
        result = generate_kql("lateral movement pass the hash detection")
        assert result["kql"]
        assert "SecurityEvent" in result["kql"]

    def test_exfil_query(self):
        result = generate_kql("large data transfer exfiltration")
        assert result["kql"]
        assert "SentBytes" in result["kql"] or "exfil" in result["kql"].lower()

    def test_privilege_escalation_query(self):
        result = generate_kql("privilege escalation admin group changes")
        assert result["kql"]

    def test_generic_fallback(self):
        result = generate_kql("this is something completely unexpected")
        assert result["kql"]
        assert "search" in result["kql"].lower() or "TimeGenerated" in result["kql"]

    def test_mock_source_when_no_api_key(self, monkeypatch):
        """When OPENAI_API_KEY is empty, source should be 'mock'."""
        monkeypatch.setattr("app.kql.generator.get_settings", lambda: _FakeSettings())
        result = generate_kql("test query")
        assert result["source"] == "mock"


class _FakeSettings:
    openai_api_key = ""
    openai_model = "gpt-4o"


class TestKqlValidator:
    """Tests for the KQL static validator."""

    def test_empty_query_is_invalid(self):
        result = validate_kql("")
        assert not result.is_valid
        assert result.errors

    def test_missing_time_filter_produces_warning(self):
        result = validate_kql("SecurityEvent | take 10")
        # Should warn about missing time filter
        assert any("time" in w.lower() for w in result.warnings)

    def test_unmatched_parens_is_error(self):
        result = validate_kql("SecurityEvent | where EventID == 4625 and (foo | take 10")
        assert not result.is_valid
        assert any("parenthes" in e.lower() for e in result.errors)

    def test_high_volume_table_warning(self):
        result = validate_kql("SecurityEvent | where TimeGenerated > ago(1h)")
        assert any("securityevent" in w.lower() for w in result.warnings)

    def test_valid_query_passes(self):
        kql = """SecurityEvent
| where TimeGenerated > ago(24h)
| where EventID == 4625
| take 100"""
        result = validate_kql(kql)
        assert result.is_valid

    def test_no_row_limit_suggestion(self):
        kql = "SecurityEvent | where TimeGenerated > ago(1h)"
        result = validate_kql(kql)
        assert any("take" in s.lower() or "limit" in s.lower() for s in result.suggestions)

    def test_dangerous_externaldata_is_error(self):
        kql = "externaldata(x:string) [@'http://evil.com/bad.csv'] | take 10"
        result = validate_kql(kql)
        assert not result.is_valid
        assert any("externaldata" in e.lower() for e in result.errors)
