"""
tests/conftest.py — shared fixtures

Key design decision: RAGEngine.__init__() loads a real FAISS index and downloads
a SentenceTransformer embedding model from Hugging Face. We don't want unit tests
to depend on network access, GPU, or a multi-second model load — that's slow,
flaky in CI, and untestable offline.

Instead, we bypass __init__ with object.__new__() and set only the attributes
each test actually needs. This isolates the *lookup logic* (which is what we
actually want to verify) from the *embedding infrastructure* (which we trust
FAISS/sentence-transformers to have already tested upstream).
"""
import sys
import types
import pytest

# rag_engine.py imports faiss and sentence_transformers at module level.
# Stub them out so `import rag_engine` works in an environment that doesn't
# have those (heavy) packages installed, and so nothing tries to hit the
# network for a model download during test collection.
if "faiss" not in sys.modules:
    fake_faiss = types.ModuleType("faiss")
    fake_faiss.read_index = lambda path: None
    # find_group()'s Pass 4 branches on the index metric to decide whether a
    # higher or a lower score means "closer", so the stub needs the constants.
    # Values match real FAISS.
    fake_faiss.METRIC_INNER_PRODUCT = 0
    fake_faiss.METRIC_L2 = 1
    sys.modules["faiss"] = fake_faiss

import faiss  # noqa: E402  (the stub above, or the real thing if installed)

if "sentence_transformers" not in sys.modules:
    fake_st = types.ModuleType("sentence_transformers")

    class _FakeSentenceTransformer:
        def __init__(self, *args, **kwargs):
            pass

        def encode(self, *args, **kwargs):
            raise NotImplementedError(
                "encode() should never be called in unit tests — "
                "mock semantic_search()/vector_search() instead."
            )

    fake_st.SentenceTransformer = _FakeSentenceTransformer
    sys.modules["sentence_transformers"] = fake_st

from rag_engine import RAGEngine  # noqa: E402


@pytest.fixture
def rag():
    """
    A RAGEngine instance with __init__ bypassed. Populated with a small,
    hand-built dataset that exercises the tricky parts of find_group():
    exact match, word-boundary safety (APT1 vs APT12), and abbreviation
    matching (lazarus -> Lazarus Group).
    """
    engine = object.__new__(RAGEngine)

    engine._cti_by_group = {
        "APT1": {"cti_summary": "APT1 is a China-based espionage group.",
                  "cti_techniques": "T1059 T1071"},
        "APT12": {"cti_summary": "APT12 targets media and government.",
                   "cti_techniques": "T1053"},
        "Lazarus Group": {"cti_summary": "Lazarus Group is a North Korea-linked actor.",
                            "cti_techniques": "T1055 T1027 T1497"},
    }

    engine.mitre_lookup = {
        "T1059": {"name": "Command and Scripting Interpreter",
                   "description": "Adversaries may abuse command and script interpreters.",
                   "domain": "enterprise-attack"},
        "T1071": {"name": "Application Layer Protocol",
                   "description": "Adversaries may communicate using OSI application layer protocols.",
                   "domain": "enterprise-attack"},
        "T1053": {"name": "Scheduled Task/Job",
                   "description": "Adversaries may abuse task scheduling functionality.",
                   "domain": "enterprise-attack"},
        # Note: T1055, T1027, T1497 deliberately omitted to test the
        # "unknown technique" fallback path in enrich_ttps().
    }

    # Pass 1.5 looks up MITRE codename aliases. Empty here so these tests
    # exercise Passes 1-4 only; alias resolution has its own tests.
    engine._alias_to_group = {}

    engine.metadata = []
    # Pass 4 reads index.metric_type to know which direction "closer" is.
    engine.index = types.SimpleNamespace(metric_type=faiss.METRIC_L2)
    engine.model = None

    return engine
