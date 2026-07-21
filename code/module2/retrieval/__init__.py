"""Public API for Module 2 retrieval."""

from typing import Any

from .chunking import Chunk, chunk_documents

_INGEST_EXPORTS = {"build_index", "decode_metadata"}
_RETRIEVER_EXPORTS = {
    "CONFIG_DENSE",
    "CONFIG_FULL",
    "CONFIG_HYBRID",
    "CONFIG_RERANK",
    "RetrievalConfig",
    "RetrievedChunk",
    "Retriever",
    "build_query",
}


def __getattr__(name: str) -> Any:
    """Load model-bearing retrieval modules only when their API is requested."""

    if name in _INGEST_EXPORTS:
        from . import ingest

        return getattr(ingest, name)
    if name in _RETRIEVER_EXPORTS:
        from . import retrievers

        return getattr(retrievers, name)
    raise AttributeError(name)

__all__ = [
    "Chunk",
    "CONFIG_DENSE",
    "CONFIG_FULL",
    "CONFIG_HYBRID",
    "CONFIG_RERANK",
    "RetrievalConfig",
    "RetrievedChunk",
    "Retriever",
    "build_index",
    "build_query",
    "chunk_documents",
    "decode_metadata",
]
