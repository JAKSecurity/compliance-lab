# compliance_lab/controls.py
"""ControlStore — RAG pipeline for NIST 800-53 controls via LlamaIndex + Qdrant."""

from pathlib import Path

import yaml
from llama_index.core import Document, Settings, StorageContext, VectorStoreIndex
from llama_index.vector_stores.qdrant import QdrantVectorStore
from qdrant_client import QdrantClient


class ControlStore:
    """Loads NIST 800-53 controls, indexes in Qdrant, retrieves by query."""

    def __init__(self, documents: list[Document]):
        self._documents = documents
        self._index = None
        self._retriever = None

    @classmethod
    def from_yaml(cls, yaml_path: Path) -> "ControlStore":
        """Load controls from a YAML file. Each entry becomes a Document."""
        if not yaml_path.exists():
            raise FileNotFoundError(f"Controls file not found: {yaml_path}")

        with open(yaml_path) as f:
            data = yaml.safe_load(f)

        documents = []
        for ctrl in data["controls"]:
            doc = Document(
                text=ctrl["text"],
                metadata={
                    "control_id": ctrl["id"],
                    "family": ctrl["family"],
                    "title": ctrl["title"],
                },
                doc_id=ctrl["id"].lower(),
            )
            documents.append(doc)

        return cls(documents)

    def build_index(self, embed_model=None, collection_name: str = "nist_800_53"):
        """Index all documents in an in-memory Qdrant collection."""
        if embed_model is not None:
            Settings.embed_model = embed_model

        client = QdrantClient(location=":memory:")
        vector_store = QdrantVectorStore(client=client, collection_name=collection_name)
        storage_context = StorageContext.from_defaults(vector_store=vector_store)

        self._index = VectorStoreIndex.from_documents(
            self._documents,
            storage_context=storage_context,
        )
        self._retriever = self._index.as_retriever(similarity_top_k=1)

    def retrieve(self, query: str) -> str:
        """Retrieve the most relevant control text for a query."""
        if self._retriever is None:
            raise RuntimeError("ControlStore not indexed. Call build_index() first.")
        nodes = self._retriever.retrieve(query)
        return nodes[0].text

    def is_indexed(self) -> bool:
        return self._index is not None

    def control_count(self) -> int:
        return len(self._documents)

    @property
    def documents(self) -> list[Document]:
        return list(self._documents)
