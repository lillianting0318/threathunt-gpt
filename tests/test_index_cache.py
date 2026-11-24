"""
tests/test_index_cache.py — the enriched-index cache (M2)

Two things must hold:
  1. the cache key changes whenever anything the enriched index depends on
     changes (input files, embedding model, ICS data), and only then
  2. a cache is used only when its key matches and it is intact; anything
     else falls back to a rebuild instead of crashing

faiss is stubbed in conftest, so read/write are monkeypatched here with a
tiny fake index. The real round trip is exercised by starting the app.
"""
import json
import os

import pytest

import rag_engine
from rag_engine import RAGEngine, compute_index_cache_key


@pytest.fixture
def inputs(tmp_path):
    paths = []
    for name, content in [("index.faiss", b"base-index"),
                          ("meta.json", b"[]"),
                          ("mitre.json", b'{"entries": []}')]:
        p = tmp_path / name
        p.write_bytes(content)
        paths.append(str(p))
    return paths


# ---------------------------------------------------------------------------
# cache key
# ---------------------------------------------------------------------------

def test_key_is_stable_for_identical_inputs(inputs):
    assert compute_index_cache_key(inputs, "model-a") == compute_index_cache_key(inputs, "model-a")


def test_key_changes_when_an_input_file_changes(inputs):
    before = compute_index_cache_key(inputs, "model-a")
    with open(inputs[2], "wb") as f:          # e.g. a new ATT&CK release
        f.write(b'{"entries": [{"id": "T9999"}]}')
    assert compute_index_cache_key(inputs, "model-a") != before


def test_key_changes_when_the_embedding_model_changes(inputs):
    assert compute_index_cache_key(inputs, "model-a") != compute_index_cache_key(inputs, "model-b")


def test_key_changes_when_ics_data_changes(inputs, monkeypatch):
    before = compute_index_cache_key(inputs, "model-a")
    monkeypatch.setitem(rag_engine.ICS_TECHNIQUES, "T0999", {"name": "x", "description": "y", "domain": "ics-attack"})
    assert compute_index_cache_key(inputs, "model-a") != before


def test_key_changes_when_cache_version_is_bumped(inputs, monkeypatch):
    before = compute_index_cache_key(inputs, "model-a")
    monkeypatch.setattr(rag_engine, "INDEX_CACHE_VERSION", "999")
    assert compute_index_cache_key(inputs, "model-a") != before


# ---------------------------------------------------------------------------
# load / save
# ---------------------------------------------------------------------------

class FakeIndex:
    def __init__(self, ntotal):
        self.ntotal = ntotal


@pytest.fixture
def fake_faiss_io(monkeypatch):
    """write_index stores ntotal in the file; read_index reads it back."""
    def write_index(index, path):
        with open(path, "w") as f:
            f.write(str(index.ntotal))

    def read_index(path):
        with open(path) as f:
            return FakeIndex(int(f.read()))

    monkeypatch.setattr(rag_engine.faiss, "write_index", write_index, raising=False)
    monkeypatch.setattr(rag_engine.faiss, "read_index", read_index)


def _engine(ntotal=2):
    engine = object.__new__(RAGEngine)
    engine.index = FakeIndex(ntotal)
    engine.metadata = [{"title": f"T{i}"} for i in range(ntotal)]
    return engine


def test_save_then_load_round_trip(tmp_path, fake_faiss_io):
    _engine(3)._save_index_cache(str(tmp_path), "key-1")

    fresh = _engine(0)
    assert fresh._load_index_cache(str(tmp_path), "key-1") is True
    assert fresh.index.ntotal == 3
    assert len(fresh.metadata) == 3


def test_load_rejects_a_different_key(tmp_path, fake_faiss_io):
    _engine(3)._save_index_cache(str(tmp_path), "key-1")
    fresh = _engine(0)
    assert fresh._load_index_cache(str(tmp_path), "key-2") is False
    assert fresh.index.ntotal == 0          # untouched


def test_load_returns_false_when_there_is_no_cache(tmp_path, fake_faiss_io):
    assert _engine(0)._load_index_cache(str(tmp_path / "missing"), "key-1") is False


def test_load_rejects_index_and_metadata_that_disagree(tmp_path, fake_faiss_io):
    _engine(3)._save_index_cache(str(tmp_path), "key-1")
    with open(tmp_path / RAGEngine._CACHE_META, "w") as f:
        json.dump([{"title": "T0"}], f)     # 1 metadata row for 3 vectors
    assert _engine(0)._load_index_cache(str(tmp_path), "key-1") is False


def test_load_rejects_corrupt_metadata(tmp_path, fake_faiss_io):
    _engine(3)._save_index_cache(str(tmp_path), "key-1")
    (tmp_path / RAGEngine._CACHE_META).write_text("{not json")
    assert _engine(0)._load_index_cache(str(tmp_path), "key-1") is False


def test_save_does_not_raise_on_an_unwritable_directory(tmp_path, fake_faiss_io):
    blocker = tmp_path / "a_file"
    blocker.write_text("x")
    # cache_dir "under" a regular file cannot be created
    _engine(1)._save_index_cache(str(blocker / "cache"), "key-1")
