"""
tests/test_rag_engine.py — core lookup logic

Covers the group resolution in RAGEngine.find_group():
  1.  exact match
  1.5 MITRE codename alias table
  2.  word-boundary substring match  (must NOT let "APT1" match "APT12")
  3.  abbreviation match             ("lazarus" -> "Lazarus Group")
  4.  semantic search fallback, gated by distance AND margin

Also covers enrich_ttps()'s three-way fallback:
  known enterprise technique -> known ICS technique -> unknown technique stub.
"""
import pytest
from rag_engine import ICS_TECHNIQUES


# ---------------------------------------------------------------------------
# Pass 1: exact match
# ---------------------------------------------------------------------------

def test_find_group_exact_match(rag):
    assert rag.find_group("APT1") == "APT1"


def test_find_group_exact_match_case_insensitive(rag):
    assert rag.find_group("apt1") == "APT1"
    assert rag.find_group("lazarus group") == "Lazarus Group"


# ---------------------------------------------------------------------------
# Pass 2: word-boundary match — the specific bug this layer was built to avoid
# ---------------------------------------------------------------------------

def test_find_group_does_not_confuse_apt1_and_apt12(rag):
    """
    Regression test for the bug the docstring calls out directly:
    a naive substring match would let "APT1" match inside "APT12".
    Word-boundary matching must prevent that.
    """
    assert rag.find_group("APT1") == "APT1"
    assert rag.find_group("APT12") == "APT12"


def test_find_group_word_boundary_in_longer_query(rag):
    # "APT1" appears as a substring of the query but is followed by a
    # non-alphanumeric boundary, so it should still match APT1 specifically.
    assert rag.find_group("investigating APT1 activity") == "APT1"


def test_find_group_rejects_partial_digit_match(rag, monkeypatch):
    # A query containing "APT1" immediately followed by another digit
    # should not resolve to "APT1" via Pass 2 (would incorrectly match
    # inside "APT12"-like tokens if boundary checking were broken).
    # Passes 1-3 correctly find no match here, so Pass 4 runs with an
    # empty retrieval and must return None rather than inventing a group.
    monkeypatch.setattr(rag, "semantic_search", lambda query, top_k=20: [])
    assert rag.find_group("APT123456") is None


# ---------------------------------------------------------------------------
# Pass 3: abbreviation / substring-of-name match
# ---------------------------------------------------------------------------

def test_find_group_abbreviation_match(rag):
    assert rag.find_group("lazarus") == "Lazarus Group"


# ---------------------------------------------------------------------------
# Pass 4: semantic search fallback
# ---------------------------------------------------------------------------

def _hits(*pairs):
    """Build a fake semantic_search() return value from (title, score) pairs."""
    return [
        {"source_type": "cti_summary", "title": title, "score": score}
        for title, score in pairs
    ]


def test_find_group_falls_back_to_semantic_search(rag, monkeypatch):
    """
    No exact/word-boundary/abbreviation match exists for this query, so
    find_group() falls through to Pass 4 and resolves on the retrieval —
    a close match (1.10 < 1.45) with a wide margin (0.50 > 0.20).
    """
    monkeypatch.setattr(
        rag,
        "semantic_search",
        lambda query, top_k=20: _hits(("Lazarus Group", 1.10), ("APT1", 1.60)),
    )
    assert rag.find_group(
        "a group known for supply chain attacks and destructive wipers"
    ) == "Lazarus Group"


def test_find_group_returns_none_when_nothing_matches(rag, monkeypatch):
    monkeypatch.setattr(rag, "semantic_search", lambda query, top_k=20: [])
    assert rag.find_group("completely unrelated nonsense query") is None


# ---------------------------------------------------------------------------
# Pass 4's two guards. Both are needed: each rejects what the other accepts.
# Thresholds here are tuned on eval/dataset.jsonl; see eval/diagnose_margin.py.
# ---------------------------------------------------------------------------

def test_find_group_rejects_a_distant_best_match(rag, monkeypatch):
    """
    Junk queries ("qwertyuiop") retrieve a single group with nothing near it,
    so the margin check passes trivially. Only the distance bound stops them.
    """
    monkeypatch.setattr(
        rag, "semantic_search", lambda query, top_k=20: _hits(("APT1", 1.80))
    )
    assert rag.find_group("qwertyuiop") is None


def test_find_group_rejects_a_coin_flip(rag, monkeypatch):
    """
    Both candidates are inside the distance bound, but 0.004 apart: the
    embedding cannot tell them apart, so answering at all is guessing.
    This is the real "Iranian group that used the Shamoon wiper" case.
    """
    monkeypatch.setattr(
        rag,
        "semantic_search",
        lambda query, top_k=20: _hits(("APT12", 1.332), ("APT1", 1.336)),
    )
    assert rag.find_group("an espionage group that targets media outlets") is None


def test_find_group_ignores_non_group_hits_when_measuring_margin(rag, monkeypatch):
    """
    The index is ~97% MITRE technique vectors after enrich_index_with_mitre().
    The margin must be measured between *groups*, not against whatever
    technique happens to rank in between, or a good match gets rejected by a
    neighbour it was never competing with.
    """
    monkeypatch.setattr(
        rag,
        "semantic_search",
        lambda query, top_k=20: [
            {"source_type": "mitre_technique", "title": "T1059", "score": 1.05},
            {"source_type": "cti_summary", "title": "Lazarus Group", "score": 1.10},
            {"source_type": "mitre_technique", "title": "T1071", "score": 1.12},
            {"source_type": "cti_summary", "title": "APT1", "score": 1.40},
        ],
    )
    assert rag.find_group(
        "destructive wiper attacks attributed to a state actor"
    ) == "Lazarus Group"


def test_find_group_ignores_groups_not_in_the_cti_data(rag, monkeypatch):
    """
    enrich_index_with_mitre() puts vectors in the index that have no entry in
    _cti_by_group. Returning one of those would hand the agents a group name
    they cannot look up, so they must not count as candidates at all —
    including when one wins the retrieval outright.
    """
    monkeypatch.setattr(
        rag,
        "semantic_search",
        lambda query, top_k=20: _hits(("Wizard Spider", 1.10), ("APT1", 1.15)),
    )
    # Wizard Spider ranks first but has no CTI entry, so it is dropped and
    # APT1 is left uncontested. Note what this costs: a 0.05 loss becomes the
    # answer purely because its only rival was unusable.
    assert rag.find_group("a ransomware crew running TrickBot") == "APT1"


# ---------------------------------------------------------------------------
# get_cti_summary / get_ttp_ids
# ---------------------------------------------------------------------------

def test_get_cti_summary_known_group(rag):
    assert "espionage" in rag.get_cti_summary("APT1")


def test_get_cti_summary_unknown_group_returns_default(rag):
    assert rag.get_cti_summary("Not A Real Group") == "No CTI summary available."


def test_get_ttp_ids_parses_whitespace_separated_ids(rag):
    assert rag.get_ttp_ids("APT1") == ["T1059", "T1071"]


def test_get_ttp_ids_unknown_group_returns_empty_list(rag):
    assert rag.get_ttp_ids("Not A Real Group") == []


# ---------------------------------------------------------------------------
# enrich_ttps — enterprise / ICS / unknown fallback chain
# ---------------------------------------------------------------------------

def test_enrich_ttps_known_enterprise_technique(rag):
    result = rag.enrich_ttps(["T1059"])
    assert result[0]["name"] == "Command and Scripting Interpreter"
    assert result[0]["domain"] == "enterprise-attack"


def test_enrich_ttps_falls_back_to_ics_technique(rag):
    # T0800 is not in mitre_lookup (that's the enterprise set) but is in
    # the module-level ICS_TECHNIQUES fallback table.
    assert "T0800" in ICS_TECHNIQUES
    result = rag.enrich_ttps(["T0800"])
    assert result[0]["name"] == "Activate Firmware Update Mode"
    assert result[0]["domain"] == "ics-attack"


def test_enrich_ttps_unknown_technique_gets_generic_stub(rag):
    result = rag.enrich_ttps(["T9999"])
    assert result[0]["id"] == "T9999"
    assert result[0]["domain"] == "unknown"
    assert "attack.mitre.org/techniques/T9999" in result[0]["description"]


def test_enrich_ttps_description_is_truncated_to_500_chars(rag):
    rag.mitre_lookup["T_LONG"] = {
        "name": "Long Technique",
        "description": "x" * 1000,
        "domain": "enterprise-attack",
    }
    result = rag.enrich_ttps(["T_LONG"])
    assert len(result[0]["description"]) == 500


def test_enrich_ttps_preserves_input_order(rag):
    result = rag.enrich_ttps(["T1071", "T1059", "T9999"])
    assert [r["id"] for r in result] == ["T1071", "T1059", "T9999"]
