"""
Tests for investigation playbooks.
"""

from __future__ import annotations

import pytest

from app.playbooks import PLAYBOOK_REGISTRY, get_playbook, ALL_PLAYBOOKS
from app.playbooks.base import _sanitise_substitution


class TestPlaybookRegistry:
    """Tests that all playbooks are correctly registered."""

    def test_all_playbooks_registered(self):
        assert len(PLAYBOOK_REGISTRY) == len(ALL_PLAYBOOKS)

    def test_get_playbook_returns_instance(self):
        for name in PLAYBOOK_REGISTRY:
            pb = get_playbook(name)
            assert pb is not None
            assert pb.name == name

    def test_get_unknown_playbook_raises(self):
        with pytest.raises(KeyError):
            get_playbook("NonExistentPlaybook")

    def test_all_playbooks_have_steps(self):
        for name in PLAYBOOK_REGISTRY:
            pb = get_playbook(name)
            assert len(pb.steps) > 0, f"{name} has no steps"

    def test_all_steps_have_kql(self):
        for name in PLAYBOOK_REGISTRY:
            pb = get_playbook(name)
            for step in pb.steps:
                assert step.kql.strip(), f"{name}: step '{step.title}' has empty KQL"

    def test_all_steps_have_title(self):
        for name in PLAYBOOK_REGISTRY:
            pb = get_playbook(name)
            for step in pb.steps:
                assert step.title.strip(), f"{name}: step has empty title"

    def test_to_dict_serialisation(self):
        pb = get_playbook(list(PLAYBOOK_REGISTRY.keys())[0])
        d = pb.to_dict()
        assert "name" in d
        assert "steps" in d
        assert isinstance(d["steps"], list)


class TestSanitiseSubstitution:
    """Tests for the KQL template injection prevention helper."""

    def test_allows_normal_username(self):
        assert _sanitise_substitution("john.doe") == "john.doe"

    def test_allows_upn(self):
        result = _sanitise_substitution("john.doe@contoso.com")
        assert "john.doe@contoso.com" == result

    def test_strips_kql_injection(self):
        # A pipe could attempt to inject new clauses
        result = _sanitise_substitution("foo | drop table Sensitive")
        assert "|" not in result

    def test_strips_semicolons(self):
        result = _sanitise_substitution("foo; bar")
        assert ";" not in result

    def test_allows_ip_address(self):
        result = _sanitise_substitution("192.168.1.1")
        assert result == "192.168.1.1"
