"""Evaluate the fixed Module 2 retrieval ablation configurations."""

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path
from statistics import fmean
from typing import Any, Iterable, Iterator, Sequence

from ..kb_loader import DEVICE_PROFILE_PLACEHOLDER, load_gold_set
from .retrievers import (
    CONFIG_DENSE,
    CONFIG_FULL,
    CONFIG_HYBRID,
    CONFIG_RERANK,
    RetrievalConfig,
    Retriever,
)

RESULTS_DIR = Path(__file__).resolve().parent.parent / "results"
TOP_K = 5

CONFIGURATIONS: tuple[tuple[str, RetrievalConfig], ...] = (
    ("dense", CONFIG_DENSE),
    ("hybrid_bm25_rrf", CONFIG_HYBRID),
    ("rerank", CONFIG_RERANK),
    ("full_decomposition", CONFIG_FULL),
)


@dataclass(frozen=True, slots=True)
class EvaluationQuery:
    """One expanded gold-set query, including queries that will be skipped."""

    attack_type: str
    section: str
    device_category: str
    expected_doc_ids: tuple[str, ...]


def recall_at_k(
    retrieved_doc_ids: Sequence[str], expected_doc_ids: Iterable[str], k: int
) -> float:
    """Return document-level recall within the first ``k`` retrieved chunks."""

    if k < 0:
        raise ValueError("k must be non-negative")
    expected = set(expected_doc_ids)
    if not expected:
        raise ValueError("recall is undefined for an empty expected document set")
    hits = expected.intersection(retrieved_doc_ids[:k])
    return len(hits) / len(expected)


def mrr(
    retrieved_doc_ids: Sequence[str], expected_doc_ids: Iterable[str]
) -> float:
    """Return reciprocal rank of the first chunk from an expected document."""

    expected = set(expected_doc_ids)
    if not expected:
        raise ValueError("MRR is undefined for an empty expected document set")
    for rank, doc_id in enumerate(retrieved_doc_ids, start=1):
        if doc_id in expected:
            return 1.0 / rank
    return 0.0


def resolve_expected_docs(
    gold_set: dict[str, Any],
    attack_type: str,
    section: str,
    device_category: str,
) -> list[str]:
    """Resolve the device-profile placeholder for one gold-set cell."""

    profile_doc_id = gold_set["device_profile_resolution"][device_category]
    return [
        profile_doc_id if doc_id == DEVICE_PROFILE_PLACEHOLDER else doc_id
        for doc_id in gold_set["entries"][attack_type][section]
    ]


def iter_evaluation_queries(gold_set: dict[str, Any]) -> Iterator[EvaluationQuery]:
    """Expand all 60 gold cells across every configured device category."""

    device_categories = tuple(gold_set["device_profile_resolution"])
    for attack_type, sections in gold_set["entries"].items():
        for section in gold_set["report_sections"]:
            if section not in sections:
                raise ValueError(
                    f"gold set has no {section!r} entry for {attack_type!r}"
                )
            for device_category in device_categories:
                yield EvaluationQuery(
                    attack_type=attack_type,
                    section=section,
                    device_category=device_category,
                    expected_doc_ids=tuple(
                        resolve_expected_docs(
                            gold_set, attack_type, section, device_category
                        )
                    ),
                )


def evaluate_query(
    retriever: Retriever,
    config_name: str,
    config: RetrievalConfig,
    query: EvaluationQuery,
) -> dict[str, Any]:
    """Retrieve and score one non-empty evaluation query."""

    if not query.expected_doc_ids:
        raise ValueError("cannot evaluate a query with an empty expected document set")
    retrieved = retriever.retrieve(
        query.section,
        query.attack_type,
        query.device_category,
        config,
    )
    retrieved_doc_ids = [chunk.doc_id for chunk in retrieved]
    return {
        "config": config_name,
        "attack_type": query.attack_type,
        "section": query.section,
        "device_category": query.device_category,
        "recall_at_5": recall_at_k(
            retrieved_doc_ids, query.expected_doc_ids, TOP_K
        ),
        "mrr": mrr(retrieved_doc_ids, query.expected_doc_ids),
        "retrieved_doc_ids": "|".join(retrieved_doc_ids),
    }


def _aggregate_rows(
    config_name: str,
    rows: list[dict[str, Any]],
    n_skipped: int,
) -> dict[str, Any]:
    return {
        "config": config_name,
        "mean_recall_at_5": fmean(row["recall_at_5"] for row in rows),
        "mean_mrr": fmean(row["mrr"] for row in rows),
        "n_queries": len(rows),
        "n_skipped": n_skipped,
    }


def run_evaluation(
    retriever: Retriever | None = None,
    gold_set: dict[str, Any] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Run all four fixed configurations and return summary, section, and detail rows."""

    if gold_set is None:
        gold_set = load_gold_set()
    if retriever is None:
        retriever = Retriever()

    queries = list(iter_evaluation_queries(gold_set))
    summary_rows: list[dict[str, Any]] = []
    section_rows: list[dict[str, Any]] = []
    detail_rows: list[dict[str, Any]] = []

    for config_name, config in CONFIGURATIONS:
        config_rows: list[dict[str, Any]] = []
        skipped_by_section = {
            section: 0 for section in gold_set["report_sections"]
        }
        for query in queries:
            if not query.expected_doc_ids:
                skipped_by_section[query.section] += 1
                continue
            row = evaluate_query(retriever, config_name, config, query)
            config_rows.append(row)
            detail_rows.append(row)

        n_skipped = sum(skipped_by_section.values())
        summary_rows.append(_aggregate_rows(config_name, config_rows, n_skipped))
        for section in gold_set["report_sections"]:
            rows = [row for row in config_rows if row["section"] == section]
            aggregate = _aggregate_rows(
                config_name, rows, skipped_by_section[section]
            )
            aggregate["section"] = section
            section_rows.append(aggregate)

    return summary_rows, section_rows, detail_rows


def _write_csv(
    path: Path, fieldnames: list[str], rows: list[dict[str, Any]]
) -> None:
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def write_results(
    summary_rows: list[dict[str, Any]],
    section_rows: list[dict[str, Any]],
    detail_rows: list[dict[str, Any]],
) -> None:
    """Write the three evaluation CSV files under ``module2/results``."""

    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    _write_csv(
        RESULTS_DIR / "retrieval_ablation.csv",
        ["config", "mean_recall_at_5", "mean_mrr", "n_queries", "n_skipped"],
        summary_rows,
    )
    _write_csv(
        RESULTS_DIR / "retrieval_ablation_by_section.csv",
        [
            "config",
            "section",
            "mean_recall_at_5",
            "mean_mrr",
            "n_queries",
            "n_skipped",
        ],
        section_rows,
    )
    _write_csv(
        RESULTS_DIR / "retrieval_ablation_details.csv",
        [
            "config",
            "attack_type",
            "section",
            "device_category",
            "recall_at_5",
            "mrr",
            "retrieved_doc_ids",
        ],
        detail_rows,
    )


def print_summary(summary_rows: list[dict[str, Any]]) -> None:
    """Print a compact, fixed-width summary table."""

    print(f"{'config':<20} {'Recall@5':>9} {'MRR':>9} {'queries':>8} {'skipped':>8}")
    for row in summary_rows:
        print(
            f"{row['config']:<20} "
            f"{row['mean_recall_at_5']:>9.4f} "
            f"{row['mean_mrr']:>9.4f} "
            f"{row['n_queries']:>8} "
            f"{row['n_skipped']:>8}"
        )


def main() -> None:
    """Run the fixed ablation, write CSV outputs, and print its summary."""

    summary_rows, section_rows, detail_rows = run_evaluation()
    write_results(summary_rows, section_rows, detail_rows)
    print_summary(summary_rows)


if __name__ == "__main__":
    main()
