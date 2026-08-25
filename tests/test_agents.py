"""
tests/test_agents.py — agent-layer contract tests

These test the agents' input/output contracts using a fake RAG object
(simple duck-typed stand-in, not a real RAGEngine) so each agent is
tested in isolation from the retrieval layer.

The one external dependency here is the Groq LLM call inside
run_answer_agent(). We never call the real API in tests — GROQ_API_KEY
is guaranteed unset via monkeypatch, so _call_llm() takes its documented
"no API key configured" branch and returns deterministically, offline.
"""
import pytest

from agents.cti_agent import run_cti_agent
from agents.ttp_agent import run_ttp_agent
from agents.answer_agent import (
    run_answer_agent,
    _generate_yara,
    _generate_kql,
    _generate_spl,
    _call_llm,
)


class FakeRAG:
    """Minimal stand-in for RAGEngine — only implements what the agents call."""

    def __init__(self, groups=None, ttps=None):
        self._groups = groups or {}
        self._ttps = ttps or {}

    def find_group(self, query):
        return query if query in self._groups else None

    def get_group_names(self):
        return sorted(self._groups.keys())

    def get_cti_summary(self, group_name):
        return self._groups.get(group_name, "No CTI summary available.")

    def get_ttp_ids(self, group_name):
        return self._ttps.get(group_name, [])

    def enrich_ttps(self, ttp_ids):
        return [{"id": t, "name": f"Technique {t}", "description": "", "domain": "enterprise-attack"} for t in ttp_ids]


# ---------------------------------------------------------------------------
# run_cti_agent
# ---------------------------------------------------------------------------

def test_cti_agent_found_group():
    rag = FakeRAG(groups={"APT1": "APT1 is a China-based espionage group."})
    result = run_cti_agent("APT1", rag)
    assert result["status"] == "ok"
    assert result["group"] == "APT1"
    assert result["summary"] == "APT1 is a China-based espionage group."


def test_cti_agent_group_not_found():
    rag = FakeRAG(groups={"APT1": "..."})
    result = run_cti_agent("NotAGroup", rag)
    assert result["status"] == "not_found"
    assert "APT1" in result["summary"]  # available groups listed for the user


# ---------------------------------------------------------------------------
# run_ttp_agent
# ---------------------------------------------------------------------------

def test_ttp_agent_ok_with_ttps():
    rag = FakeRAG(groups={"APT1": "..."}, ttps={"APT1": ["T1059", "T1071"]})
    result = run_ttp_agent("APT1", rag)
    assert result["status"] == "ok"
    assert result["ttp_count"] == 2
    assert [t["id"] for t in result["ttps"]] == ["T1059", "T1071"]


def test_ttp_agent_group_not_found():
    rag = FakeRAG(groups={})
    result = run_ttp_agent("NotAGroup", rag)
    assert result["status"] == "not_found"
    assert result["ttp_count"] == 0


def test_ttp_agent_group_found_but_no_ttps():
    rag = FakeRAG(groups={"APT1": "..."}, ttps={})
    result = run_ttp_agent("APT1", rag)
    assert result["status"] == "no_ttps"
    assert result["ttps"] == []


# ---------------------------------------------------------------------------
# _call_llm — offline branch (no GROQ_API_KEY configured)
# ---------------------------------------------------------------------------

def test_call_llm_without_api_key_returns_setup_message(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = _call_llm("any prompt")
    assert "GROQ_API_KEY" in result


# ---------------------------------------------------------------------------
# Detection rule generators — format checks only.
#
# These deliberately do NOT assert the generated YARA/KQL/SPL is
# semantically correct threat-hunting logic — verifying that requires
# YARA/KQL/SPL expertise this project doesn't claim to have yet. What we
# CAN and should own: the generator produces syntactically well-formed
# output with the right group name and TTP IDs threaded through it.
# ---------------------------------------------------------------------------

SAMPLE_TTPS = [
    {"id": "T1059", "name": "Command and Scripting Interpreter", "description": "", "domain": "enterprise-attack"},
    {"id": "T1071", "name": "Application Layer Protocol", "description": "", "domain": "enterprise-attack"},
]


def test_generate_yara_produces_valid_rule_skeleton():
    rule = _generate_yara("APT1", SAMPLE_TTPS)
    assert rule.startswith("rule ThreatHunt_APT1")
    assert "condition:" in rule
    assert "any of them" in rule
    assert "T1059" in rule and "T1071" in rule


def test_generate_yara_sanitizes_group_name_for_rule_identifier():
    # Group names can contain characters that aren't valid in a YARA
    # rule identifier (spaces, hyphens, etc.) — the tag must be sanitized.
    rule = _generate_yara("APT-28 Fancy Bear!", SAMPLE_TTPS)
    assert rule.startswith("rule ThreatHunt_APT_28_Fancy_Bear_")


def test_generate_yara_falls_back_to_generic_string_when_no_keyword_matches():
    unmatched_ttps = [{"id": "T0000", "name": "Some Unrelated Technique", "description": "", "domain": "enterprise-attack"}]
    rule = _generate_yara("APT1", unmatched_ttps)
    assert "suspicious_indicator" in rule


def test_generate_kql_includes_group_and_ttps():
    query = _generate_kql("APT1", SAMPLE_TTPS)
    assert "APT1" in query
    assert "T1059" in query
    assert "DeviceProcessEvents" in query  # sanity check it's actually KQL-shaped


def test_generate_spl_includes_group_and_ttps():
    query = _generate_spl("APT1", SAMPLE_TTPS)
    assert 'threat_group="APT1"' in query
    assert "T1059" in query
    assert "tstats" in query  # sanity check it's actually SPL-shaped


# ---------------------------------------------------------------------------
# run_answer_agent — full agent contract, offline
# ---------------------------------------------------------------------------

def test_run_answer_agent_returns_all_expected_fields(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    result = run_answer_agent(group="APT1", cti_summary="summary text", ttps=SAMPLE_TTPS)
    assert result["status"] == "ok"
    assert result["group"] == "APT1"
    for key in ("hunt_summary", "yara_rule", "kql_query", "spl_query"):
        assert key in result
        assert isinstance(result[key], str) and len(result[key]) > 0
