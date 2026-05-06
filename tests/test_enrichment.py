"""
Tests for entity enrichment helpers (no real API calls — uses mocking).
"""

from __future__ import annotations

import pytest

from app.enrichment.ip_enrichment import is_private_ip
from app.enrichment.hash_enrichment import detect_hash_type


class TestIsPrivateIp:
    def test_rfc1918_10x(self):
        from app.enrichment.ip_enrichment import is_private_ip
        assert is_private_ip("10.0.0.1")

    def test_rfc1918_192168(self):
        from app.enrichment.ip_enrichment import is_private_ip
        assert is_private_ip("192.168.1.1")

    def test_rfc1918_172(self):
        from app.enrichment.ip_enrichment import is_private_ip
        assert is_private_ip("172.16.0.1")

    def test_loopback(self):
        from app.enrichment.ip_enrichment import is_private_ip
        assert is_private_ip("127.0.0.1")

    def test_public_ip_is_not_private(self):
        from app.enrichment.ip_enrichment import is_private_ip
        assert not is_private_ip("8.8.8.8")

    def test_invalid_ip(self):
        from app.enrichment.ip_enrichment import is_private_ip
        assert is_private_ip("not-an-ip")


class TestDetectHashType:
    def test_md5(self):
        assert detect_hash_type("44d88612fea8a8f36de82e1278abb02f") == "md5"

    def test_sha1(self):
        assert detect_hash_type("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "sha1"

    def test_sha256(self):
        assert (
            detect_hash_type(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            )
            == "sha256"
        )

    def test_unknown_hash(self):
        assert detect_hash_type("not-a-hash") == "unknown"


class TestEnrichIpSync:
    """Tests for IP enrichment — mock HTTP calls."""

    @pytest.mark.asyncio
    async def test_private_ip_skips_external_lookup(self):
        from app.enrichment.ip_enrichment import enrich_ip
        result = await enrich_ip("10.0.0.1")
        assert result["is_private"] is True
        assert result["summary"].get("note") is not None

    @pytest.mark.asyncio
    async def test_public_ip_without_keys(self, monkeypatch):
        """Without API keys configured, returns empty data gracefully."""
        class _FakeSettings:
            virustotal_api_key = ""
            abuseipdb_api_key = ""

        monkeypatch.setattr("app.enrichment.ip_enrichment.get_settings", _FakeSettings)
        from app.enrichment.ip_enrichment import enrich_ip
        result = await enrich_ip("8.8.8.8")
        assert result["ip"] == "8.8.8.8"
        assert not result["is_private"]


class TestEnrichHashSync:
    """Tests for hash enrichment."""

    @pytest.mark.asyncio
    async def test_invalid_hash_format(self):
        from app.enrichment.hash_enrichment import enrich_hash
        result = await enrich_hash("not-a-hash")
        assert result["hash_type"] == "unknown"
        assert result["summary"].get("error")

    @pytest.mark.asyncio
    async def test_no_api_key_returns_note(self, monkeypatch):
        class _FakeSettings:
            virustotal_api_key = ""

        monkeypatch.setattr("app.enrichment.hash_enrichment.get_settings", _FakeSettings)
        from app.enrichment.hash_enrichment import enrich_hash
        result = await enrich_hash("44d88612fea8a8f36de82e1278abb02f")
        assert result["summary"].get("note")
