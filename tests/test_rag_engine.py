"""
tests/test_rag_engine.py — core lookup logic

Covers the three-layer group resolution in RAGEngine.find_group():
  1. exact match
  2. word-boundary substring match  (must NOT let "APT1" match "APT12")
  3. abbreviation match             ("lazarus" -> "Lazarus Group")
  4. semantic search fallback

Also covers enrich_ttps()'s three-way fallback:
  known enterprise technique -> known ICS technique -> unknown technique stub.

KNOWN BUG (see test_find_group_pass4_is_broken_without_the_alias below):
  find_group()'s Pass 4 calls self.vector_search(...), but RAGEngine only
  defines semantic_search(). Any query that doesn't match Pass 1-3 currently
  raises AttributeError instead of falling back to semantic search. Fix:
  rename the call on rag_engine.py line ~161 from vector_search to
  semantic_search. Tests below alias vector_search -> semantic_search via
  monkeypatch to test the *intended* Pass 4 behavior in the meantime.
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
    # Passes 1-3 correctly find no match here, so this also exercises the
    # Pass 4 fallback -> same vector_search/semantic_search alias needed
    # as in test_find_group_falls_back_to_semantic_search (see BUGS note
    # at the top of this file).
    monkeypatch.setattr(rag, "semantic_search", lambda query, top_k=3: [])
    monkeypatch.setattr(rag, "vector_search", rag.semantic_search, raising=False)
    assert rag.find_group("APT123456") is None


# ---------------------------------------------------------------------------
# Pass 3: abbreviation / substring-of-name match
# ---------------------------------------------------------------------------

def test_find_group_abbreviation_match(rag):
    assert rag.find_group("lazarus") == "Lazarus Group"


# ---------------------------------------------------------------------------
# Pass 4: semantic search fallback
# ---------------------------------------------------------------------------

def test_find_group_falls_back_to_semantic_search(rag, monkeypatch):
    """
    No exact/word-boundary/abbreviation match exists for this query, so
    find_group() must fall through to its vector-search fallback and
    resolve using whatever that search returns.
    """
    monkeypatch.setattr(
        rag,
        "semantic_search",
        lambda query, top_k=3: [
            {"source_type": "cti_summary", "title": "Lazarus Group"}
        ],
    )
    # find_group() currently calls self.vector_search(), which does not
    # exist on RAGEngine (only semantic_search() does). We alias it here
    # so this test documents the *intended* behavior of Pass 4.
    # See BUGS.md / the note in the PR description: this alias should be
    # removed once vector_search -> semantic_search is fixed in rag_engine.py.
    monkeypatch.setattr(rag, "vector_search", rag.semantic_search, raising=False)

    assert rag.find_group("a group known for supply chain attacks and destructive wipers") == "Lazarus Group"


def test_find_group_returns_none_when_nothing_matches(rag, monkeypatch):
    monkeypatch.setattr(rag, "semantic_search", lambda query, top_k=3: [])
    monkeypatch.setattr(rag, "vector_search", rag.semantic_search, raising=False)

    assert rag.find_group("completely unrelated nonsense query") is None


def test_find_group_pass4_is_broken_without_the_alias(rag):
    """
    This test documents the actual bug as of this writing: find_group()
    calls self.vector_search(), but RAGEngine only defines semantic_search().
    Once rag_engine.py is fixed to call self.semantic_search() directly,
    this test should be updated to assert the fallback works with NO
    monkeypatch alias needed, and this test can be deleted.
    """
    with pytest.raises(AttributeError):
        rag.find_group("some query with no exact or substring match at all")


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
