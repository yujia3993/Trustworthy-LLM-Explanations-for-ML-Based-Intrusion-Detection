"""Tests for retrieval micro-ablation metrics and query expansion."""

from __future__ import annotations

from collections import Counter

import pytest

from ..kb_loader import load_gold_set
from ..retrieval.evaluate import (
    EvaluationQuery,
    evaluate_query,
    iter_evaluation_queries,
    mrr,
    recall_at_k,
    resolve_expected_docs,
)
from ..retrieval.retrievers import CONFIG_DENSE, Retriever


@pytest.mark.parametrize(
    ("retrieved", "expected", "expected_recall"),
    [
        (["doc-a", "doc-b"], ["doc-a", "doc-b"], 1.0),
        (["doc-a", "other"], ["doc-a", "doc-b"], 0.5),
        (["other-a", "other-b"], ["doc-a", "doc-b"], 0.0),
        (["doc-a", "doc-a", "doc-b"], ["doc-a", "doc-b"], 1.0),
    ],
)
def test_recall_at_k_examples(retrieved, expected, expected_recall):
    assert recall_at_k(retrieved, expected, 5) == expected_recall


@pytest.mark.parametrize(
    ("retrieved", "expected", "expected_mrr"),
    [
        (["doc-a", "doc-b"], ["doc-a", "doc-b"], 1.0),
        (["other", "doc-b"], ["doc-a", "doc-b"], 0.5),
        (["other-a", "other-b"], ["doc-a", "doc-b"], 0.0),
        (["other-a", "other-b", "doc-a"], ["doc-a"], 1.0 / 3.0),
        (["other", "other", "doc-a", "doc-a"], ["doc-a"], 1.0 / 3.0),
    ],
)
def test_mrr_examples(retrieved, expected, expected_mrr):
    assert mrr(retrieved, expected) == pytest.approx(expected_mrr)


def test_recall_at_k_counts_only_the_requested_prefix():
    assert recall_at_k(["other", "doc-a"], ["doc-a"], 1) == 0.0


def test_expected_doc_resolution_replaces_device_profile():
    gold_set = load_gold_set()
    resolved = resolve_expected_docs(
        gold_set, "mirai_ack", "immediate_actions", "doorbell"
    )
    assert set(resolved) == {
        "device-doorbell-profile",
        "iot-immediate-containment",
    }


def test_query_grid_skips_exactly_eight_assertive_confidence_cells():
    queries = list(iter_evaluation_queries(load_gold_set()))
    skipped = [query for query in queries if not query.expected_doc_ids]
    skipped_cells = {(query.attack_type, query.section) for query in skipped}

    assert len(queries) == 300
    assert len(skipped) == 40
    assert skipped_cells == {
        ("mirai_ack", "confidence_notes"),
        ("mirai_syn", "confidence_notes"),
        ("mirai_udp", "confidence_notes"),
        ("mirai_udpplain", "confidence_notes"),
        ("mirai_scan", "confidence_notes"),
        ("gafgyt_combo", "confidence_notes"),
        ("gafgyt_junk", "confidence_notes"),
        ("gafgyt_scan", "confidence_notes"),
    }
    assert Counter((query.attack_type, query.section) for query in skipped) == {
        cell: 5 for cell in skipped_cells
    }


def test_dense_single_query_smoke():
    gold_set = load_gold_set()
    query = EvaluationQuery(
        attack_type="mirai_ack",
        section="attack_mechanism",
        device_category="doorbell",
        expected_doc_ids=tuple(
            resolve_expected_docs(
                gold_set, "mirai_ack", "attack_mechanism", "doorbell"
            )
        ),
    )
    row = evaluate_query(Retriever(), "dense", CONFIG_DENSE, query)

    assert 0.0 <= row["recall_at_5"] <= 1.0
    assert 0.0 <= row["mrr"] <= 1.0
