"""Integration tests for chunking and the retrieval ablation ladder."""

from __future__ import annotations

import json

import chromadb
import pytest

from ..kb_loader import load_kb_docs
from ..retrieval import (
    CONFIG_DENSE,
    CONFIG_FULL,
    CONFIG_HYBRID,
    CONFIG_RERANK,
    Retriever,
    build_index,
    chunk_documents,
    decode_metadata,
)
from ..retrieval.ingest import COLLECTION_NAME, DEFAULT_INDEX_DIR


@pytest.fixture(scope="session")
def retrieval_index():
    chunks = build_index(DEFAULT_INDEX_DIR)
    return DEFAULT_INDEX_DIR, chunks


@pytest.fixture(scope="session")
def retriever(retrieval_index):
    index_dir, _ = retrieval_index
    return Retriever(index_dir)


def test_chunking_shape_and_clean_text():
    docs = load_kb_docs()
    chunks = chunk_documents(docs)
    assert len(chunks) >= len(docs) == 38
    assert len({chunk.chunk_id for chunk in chunks}) == len(chunks)
    assert max(len(chunk.text.split()) for chunk in chunks) < 500
    for chunk in chunks:
        assert "---" not in chunk.text
        assert "doc_id:" not in chunk.text


def test_index_count_and_metadata_round_trip(retrieval_index):
    index_dir, chunks = retrieval_index
    collection = chromadb.PersistentClient(path=str(index_dir)).get_collection(
        COLLECTION_NAME
    )
    assert collection.count() == len(chunks)

    stored = collection.get(ids=[chunks[0].chunk_id], include=["metadatas"])
    raw_metadata = stored["metadatas"][0]
    assert isinstance(raw_metadata["attack_types"], str)
    assert isinstance(json.loads(raw_metadata["attack_types"]), list)
    restored = decode_metadata(raw_metadata)
    assert restored["attack_types"] == list(chunks[0].attack_types)
    assert restored["is_distractor"] is chunks[0].is_distractor


@pytest.mark.parametrize(
    "config", [CONFIG_DENSE, CONFIG_HYBRID, CONFIG_RERANK, CONFIG_FULL]
)
def test_configs_return_deterministic_top_k(retriever, config):
    first = retriever.retrieve("attack_mechanism", "mirai_ack", "doorbell", config)
    second = retriever.retrieve("attack_mechanism", "mirai_ack", "doorbell", config)
    assert len(first) == config.top_k
    assert [result.chunk_id for result in first] == [
        result.chunk_id for result in second
    ]


def test_dense_finds_mirai_ack_mechanism(retriever):
    results = retriever.retrieve(
        "attack_mechanism", "mirai_ack", "doorbell", CONFIG_DENSE
    )
    assert any(result.doc_id == "mirai-ack-flood" for result in results)


def test_dense_finds_immediate_response_material(retriever):
    results = retriever.retrieve(
        "immediate_actions", "gafgyt_udp", "webcam", CONFIG_DENSE
    )
    assert any(
        result.metadata["doc_type"] in {"remediation", "project_finding"}
        for result in results
    )


def test_full_finds_ambiguous_pair_confidence_finding(retriever):
    results = retriever.retrieve(
        "confidence_notes", "gafgyt_tcp", "security_camera", CONFIG_FULL
    )
    expected = {"finding-pair-level-assertion", "finding-no-protocol-field"}
    assert any(result.doc_id in expected for result in results)
