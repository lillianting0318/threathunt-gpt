"""
tests/test_faithfulness.py — the automatic part of the summary faithfulness eval.
"""
from eval.run_faithfulness import extract_ids, classify_ids, is_error_text


def test_extract_ids_finds_techniques_and_subtechniques_once():
    text = "Uses T1059.001 and T1566; again T1059.001. Not an ID: XT1234, T123."
    assert extract_ids(text) == ["T1059.001", "T1566"]


def test_extract_ids_handles_empty_text():
    assert extract_ids("") == []
    assert extract_ids(None) == []


def test_classify_ids_sorts_each_id_into_one_bucket():
    out = classify_ids(
        mentioned=["T1059", "T1003", "T1486", "T9999"],
        prompt_ids=["T1059"],
        group_ids=["T1059", "T1003"],
        valid_ids=["T1059", "T1003", "T1486"],
    )
    assert out == {
        "in_prompt": ["T1059"],
        "parent_of_prompt": [],
        "group_not_prompt": ["T1003"],   # the group's, but the model was not shown it
        "not_in_group": ["T1486"],       # real technique, wrong group
        "invalid": ["T9999"],            # not an ATT&CK ID
    }


def test_is_error_text_detects_llm_error_messages():
    assert is_error_text("⚠ Groq API 錯誤：timeout")
    assert is_error_text("  ⚠ GROQ_API_KEY not set")
    assert not is_error_text("APT28 is a Russian group ...")


def test_parent_of_a_given_subtechnique_is_supported():
    # Found in the first real run: the APT1 summary cited T1114 after being
    # given T1114.001 and T1114.002. That is a generalization, not an
    # unsupported technique, and the first version of this check flagged it.
    out = classify_ids(
        mentioned=["T1114"],
        prompt_ids=["T1114.001", "T1114.002"],
        group_ids=["T1114.001", "T1114.002"],
        valid_ids=["T1114", "T1114.001", "T1114.002"],
    )
    assert out["parent_of_prompt"] == ["T1114"]
    assert out["not_in_group"] == []
