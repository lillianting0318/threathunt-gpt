"""
tests/test_group_eval.py — the group-resolution eval harness itself.

An eval that miscounts is worse than no eval, so the runner's bookkeeping
gets the same treatment as product code.
"""
from eval.run_eval import run, summarize


class FakeRAG:
    def __init__(self, answers):
        self.answers = answers          # query -> (group, method)

    def resolve_group(self, query):
        return self.answers.get(query, (None, None))


DATASET = [
    {"id": "a", "query": "Fancy Bear", "expected": "APT28", "kind": "alias"},
    {"id": "b", "query": "APT1 report", "expected": "APT1", "kind": "substring_trap"},
    {"id": "c", "query": "Lazerus", "expected": "Lazarus Group", "kind": "typo_or_variant"},
    {"id": "d", "query": "Akira Kurosawa films", "expected": None, "kind": "out_of_scope"},
    {"id": "e", "query": "hello", "expected": None, "kind": "out_of_scope"},
]


def test_run_classifies_correct_wrong_and_missed():
    rag = FakeRAG({
        "Fancy Bear": ("APT28", "alias"),               # correct
        "APT1 report": ("APT12", "word_boundary"),     # wrong
        # "Lazerus" -> nothing                         # missed
        "Akira Kurosawa films": ("Akira", "word_boundary"),  # wrong (false match)
    })
    outcomes = {r["id"]: r["outcome"] for r in run(DATASET, rag)}
    assert outcomes == {"a": "correct", "b": "wrong", "c": "missed", "d": "wrong", "e": "correct"}


def test_summarize_separates_false_matches_from_wrong_groups():
    rag = FakeRAG({
        "Fancy Bear": ("APT28", "alias"),
        "APT1 report": ("APT12", "word_boundary"),
        "Akira Kurosawa films": ("Akira", "word_boundary"),
    })
    s = summarize(run(DATASET, rag))
    assert s["n"] == 5
    assert s["accuracy"] == 2 / 5
    assert s["false_match_rate_out_of_scope"] == 1 / 2   # 1 of 2 out-of-scope queries answered
    assert s["wrong_group_rate_in_scope"] == 1 / 3       # 1 of 3 in-scope queries got the wrong group
    assert s["by_method"] == {"alias": 1, "word_boundary": 2, "none": 2}
