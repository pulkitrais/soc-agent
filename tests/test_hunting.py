"""
Tests for threat hunting templates.
"""

from __future__ import annotations

from app.hunting.templates import (
    HUNTING_TEMPLATES,
    get_all_tactics,
    get_templates_by_tactic,
    get_template_by_id,
)


class TestHuntingTemplates:
    def test_templates_exist(self):
        assert len(HUNTING_TEMPLATES) > 0

    def test_all_templates_have_kql(self):
        for t in HUNTING_TEMPLATES:
            assert t.kql.strip(), f"Template {t.id} has empty KQL"

    def test_all_templates_have_unique_ids(self):
        ids = [t.id for t in HUNTING_TEMPLATES]
        assert len(ids) == len(set(ids))

    def test_get_by_id(self):
        template = get_template_by_id("hunt-001")
        assert template is not None
        assert template.id == "hunt-001"

    def test_get_by_invalid_id_returns_none(self):
        assert get_template_by_id("does-not-exist") is None

    def test_get_all_tactics(self):
        tactics = get_all_tactics()
        assert isinstance(tactics, list)
        assert len(tactics) > 0

    def test_filter_by_tactic(self):
        results = get_templates_by_tactic("Persistence")
        assert len(results) > 0
        for t in results:
            assert "Persistence" in t.mitre_tactic

    def test_filter_nonexistent_tactic_returns_empty(self):
        results = get_templates_by_tactic("Nonexistent Tactic XYZ")
        assert results == []

    def test_all_templates_have_mitre_technique_id(self):
        for t in HUNTING_TEMPLATES:
            assert t.mitre_technique_id.startswith("T"), f"{t.id} has invalid technique ID"
