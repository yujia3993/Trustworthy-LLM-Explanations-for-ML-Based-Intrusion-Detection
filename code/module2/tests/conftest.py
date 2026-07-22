"""Shared fixtures for the Module 2 test suite."""

from __future__ import annotations

import pytest

from ..retrieval import Retriever, build_index
from ..retrieval.ingest import DEFAULT_INDEX_DIR


@pytest.fixture(scope="session")
def retrieval_index():
    """Build the shared ChromaDB index exactly once per test session."""
    chunks = build_index(DEFAULT_INDEX_DIR)
    return DEFAULT_INDEX_DIR, chunks


@pytest.fixture(scope="session")
def retriever(retrieval_index):
    index_dir, _ = retrieval_index
    return Retriever(index_dir)
