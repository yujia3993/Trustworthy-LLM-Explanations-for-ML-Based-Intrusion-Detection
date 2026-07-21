"""Build the persistent dense index and BM25 sidecar for Module 2."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

import chromadb
from sentence_transformers import SentenceTransformer

from ..kb_loader import load_kb_docs
from .chunking import Chunk, chunk_documents

COLLECTION_NAME = "module2_kb_chunks"
EMBEDDING_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
DEFAULT_INDEX_DIR = Path(__file__).resolve().parent / "index"
CHUNKS_SIDECAR_NAME = "chunks.json"


@lru_cache(maxsize=1)
def load_embedding_model() -> SentenceTransformer:
    """Load the local embedding model once per process."""

    return SentenceTransformer(EMBEDDING_MODEL_NAME, local_files_only=True)


def chunk_metadata(chunk: Chunk) -> dict[str, Any]:
    """Return Chroma-compatible scalar metadata for one chunk."""

    return {
        "doc_id": chunk.doc_id,
        "section_heading": chunk.section_heading,
        "attack_family": chunk.attack_family,
        "attack_types": json.dumps(list(chunk.attack_types)),
        "device_categories": json.dumps(list(chunk.device_categories)),
        "doc_type": chunk.doc_type,
        "source": chunk.source,
        "is_distractor": chunk.is_distractor,
        "title": chunk.title,
    }


def decode_metadata(metadata: dict[str, Any]) -> dict[str, Any]:
    """Restore JSON-encoded list fields from Chroma metadata."""

    decoded = dict(metadata)
    for field in ("attack_types", "device_categories"):
        value = decoded.get(field, "[]")
        if isinstance(value, str):
            decoded[field] = json.loads(value)
    return decoded


def _sidecar_record(chunk: Chunk) -> dict[str, Any]:
    return {
        "chunk_id": chunk.chunk_id,
        "doc_id": chunk.doc_id,
        "section_heading": chunk.section_heading,
        "text": chunk.text,
        "attack_family": chunk.attack_family,
        "attack_types": list(chunk.attack_types),
        "device_categories": list(chunk.device_categories),
        "doc_type": chunk.doc_type,
        "source": chunk.source,
        "is_distractor": chunk.is_distractor,
        "title": chunk.title,
    }


def build_index(persist_dir: str | Path = DEFAULT_INDEX_DIR) -> list[Chunk]:
    """Rebuild and persist the Chroma collection plus the JSON chunk sidecar."""

    index_dir = Path(persist_dir)
    index_dir.mkdir(parents=True, exist_ok=True)

    chunks = chunk_documents(load_kb_docs())
    model = load_embedding_model()
    embeddings = model.encode(
        [chunk.text for chunk in chunks],
        batch_size=32,
        show_progress_bar=False,
        convert_to_numpy=True,
        normalize_embeddings=True,
    )

    client = chromadb.PersistentClient(path=str(index_dir))
    existing_names = {collection.name for collection in client.list_collections()}
    if COLLECTION_NAME in existing_names:
        client.delete_collection(COLLECTION_NAME)
    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"hnsw:space": "cosine"},
    )
    collection.add(
        ids=[chunk.chunk_id for chunk in chunks],
        embeddings=embeddings.tolist(),
        documents=[chunk.text for chunk in chunks],
        metadatas=[chunk_metadata(chunk) for chunk in chunks],
    )

    sidecar_path = index_dir / CHUNKS_SIDECAR_NAME
    temporary_path = index_dir / f".{CHUNKS_SIDECAR_NAME}.tmp"
    temporary_path.write_text(
        json.dumps([_sidecar_record(chunk) for chunk in chunks], indent=2) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(sidecar_path)
    return chunks


if __name__ == "__main__":
    built_chunks = build_index()
    print(f"Built {COLLECTION_NAME!r} with {len(built_chunks)} chunks in {DEFAULT_INDEX_DIR}")
