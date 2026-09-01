# tests/test_controls.py
import hashlib
from pathlib import Path

import pytest
import yaml
from llama_index.core.base.embeddings.base import BaseEmbedding

from compliance_lab.controls import ControlStore


class FakeEmbedding(BaseEmbedding):
    """Deterministic embedding for tests. No Ollama needed."""

    model_name: str = "fake"
    embed_dim: int = 8

    def _get_text_embedding(self, text: str) -> list[float]:
        h = hashlib.md5(text.encode()).hexdigest()
        return [int(h[i : i + 2], 16) / 255.0 for i in range(0, self.embed_dim * 2, 2)]

    def _get_query_embedding(self, query: str) -> list[float]:
        return self._get_text_embedding(query)

    async def _aget_query_embedding(self, query: str) -> list[float]:
        return self._get_query_embedding(query)


# --- YAML loading tests (no embedding needed) ---


def test_load_controls_from_yaml(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    assert store.control_count() >= 20


def test_loaded_controls_have_required_fields(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    for doc in store.documents:
        assert "control_id" in doc.metadata
        assert "family" in doc.metadata
        assert "title" in doc.metadata
        assert len(doc.text) > 0


def test_control_file_records_pinned_source(controls_yaml_path):
    with controls_yaml_path.open() as controls_file:
        data = yaml.safe_load(controls_file)
    assert data["source"]["tag"] == "v1.4.0"
    assert data["source"]["commit"] == "bc8a528770033611df899b3d52703fb3dc91a20d"
    assert data["source"]["catalog_version"] == "5.2.0"
    assert len(data["source"]["sha256"]) == 64


def test_ia5_1_uses_current_oscal_statement(controls_yaml_path):
    with controls_yaml_path.open() as controls_file:
        data = yaml.safe_load(controls_file)
    control = next(item for item in data["controls"] if item["id"] == "IA-5(1)")
    text = control["text"].lower()
    assert "commonly-used, expected, or compromised passwords" in text
    assert "salted key derivation function" in text
    assert "at least 8 characters" not in text
    assert "maximum age" not in text


def test_loaded_controls_span_multiple_families(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    families = {doc.metadata["family"] for doc in store.documents}
    assert len(families) >= 3


def test_ia5_1_present_in_loaded_controls(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    control_ids = {doc.metadata["control_id"] for doc in store.documents}
    assert "IA-5(1)" in control_ids


def test_control_text_contains_substance(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    for doc in store.documents:
        assert len(doc.text) >= 50


def test_from_yaml_missing_file_raises():
    with pytest.raises(FileNotFoundError, match="nonexistent"):
        ControlStore.from_yaml(Path("/nonexistent/path.yaml"))


def test_document_text_includes_control_id(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    for doc in store.documents:
        assert doc.metadata["control_id"] in doc.text


# --- Retrieval tests (use FakeEmbedding) ---


def test_index_and_retrieve_ia5_1(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    store.build_index(embed_model=FakeEmbedding())
    result = store.retrieve("IA-5(1) password-based authentication")
    # FakeEmbedding is deterministic but not semantic, so we verify retrieval
    # returns a valid control text rather than asserting which control is returned.
    assert isinstance(result, str)
    assert "Control:" in result
    assert len(result) > 50


def test_retrieve_returns_string(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    store.build_index(embed_model=FakeEmbedding())
    result = store.retrieve("access control")
    assert isinstance(result, str)
    assert len(result) > 0


def test_retrieve_before_index_raises(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    with pytest.raises(RuntimeError, match="index"):
        store.retrieve("anything")


def test_index_creates_qdrant_collection(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    assert not store.is_indexed()
    store.build_index(embed_model=FakeEmbedding())
    assert store.is_indexed()


def test_retrieve_returns_nonempty_for_valid_query(controls_yaml_path):
    store = ControlStore.from_yaml(controls_yaml_path)
    store.build_index(embed_model=FakeEmbedding())
    result = store.retrieve("audit record review analysis")
    assert len(result) > 0


def test_control_count_matches_yaml(controls_yaml_path):
    with open(controls_yaml_path) as f:
        raw = yaml.safe_load(f)
    store = ControlStore.from_yaml(controls_yaml_path)
    assert store.control_count() == len(raw["controls"])
