"""
Tests for investigation session management.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from app.investigation.session import SessionManager, InvestigationSession, EvidenceItem


@pytest.fixture()
def temp_sessions_dir(tmp_path, monkeypatch):
    """Redirect session storage to a temp dir."""
    class _FakeSettings:
        sessions_dir = tmp_path
        exports_dir = tmp_path / "exports"
        query_library_dir = tmp_path / "lib"

        def ensure_data_dirs(self):
            self.sessions_dir.mkdir(exist_ok=True)
            self.exports_dir.mkdir(exist_ok=True)
            self.query_library_dir.mkdir(exist_ok=True)

    settings = _FakeSettings()
    settings.ensure_data_dirs()
    monkeypatch.setattr("app.investigation.session.get_settings", lambda: settings)
    return tmp_path


class TestSessionManager:
    def test_create_session(self, temp_sessions_dir):
        sm = SessionManager()
        sess = sm.create(title="Test Session", severity="high")
        assert sess.id
        assert sess.title == "Test Session"
        assert sess.severity == "high"

    def test_create_then_load(self, temp_sessions_dir):
        sm = SessionManager()
        sess = sm.create(title="Load Test")
        loaded = sm.load(sess.id)
        assert loaded is not None
        assert loaded.title == "Load Test"

    def test_load_nonexistent_returns_none(self, temp_sessions_dir):
        sm = SessionManager()
        assert sm.load("nonexistent-id-9999") is None

    def test_list_sessions(self, temp_sessions_dir):
        sm = SessionManager()
        sm.create(title="Session A")
        sm.create(title="Session B")
        sessions = sm.list_sessions()
        assert len(sessions) == 2

    def test_delete_session(self, temp_sessions_dir):
        sm = SessionManager()
        sess = sm.create(title="Delete Me")
        sm.delete(sess.id)
        assert sm.load(sess.id) is None

    def test_add_note(self, temp_sessions_dir):
        sm = SessionManager()
        sess = sm.create(title="Note Test")
        sm.add_note(sess, "This is a note", title="Test Note")
        loaded = sm.load(sess.id)
        assert len(loaded.evidence) == 1
        assert loaded.evidence[0].item_type == "note"
        assert loaded.evidence[0].content == "This is a note"

    def test_add_entity(self, temp_sessions_dir):
        sm = SessionManager()
        sess = sm.create()
        sm.add_entity(sess, "ip", "8.8.8.8")
        sm.add_entity(sess, "user", "john@example.com")
        loaded = sm.load(sess.id)
        assert "8.8.8.8" in loaded.entities.get("ip", [])
        assert "john@example.com" in loaded.entities.get("user", [])

    def test_timeline_updated_on_note(self, temp_sessions_dir):
        sm = SessionManager()
        sess = sm.create(title="Timeline Test")
        sm.add_note(sess, "test")
        loaded = sm.load(sess.id)
        assert len(loaded.timeline) >= 1

    def test_session_serialisation_roundtrip(self, temp_sessions_dir):
        sm = SessionManager()
        sess = sm.create(title="Roundtrip", description="test desc")
        sm.add_note(sess, "note content")
        sm.add_entity(sess, "ip", "1.2.3.4")
        loaded = sm.load(sess.id)
        d = loaded.to_dict()
        restored = InvestigationSession.from_dict(json.loads(json.dumps(d)))
        assert restored.title == "Roundtrip"
        assert len(restored.evidence) == 1
