"""Run the frozen Module 3 evaluation protocol over a case split."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from ..generation import (
    GEN_FULL_RAG,
    GEN_NAIVE_RAG,
    GEN_NO_RAG,
    GEN_SELF_CHECK,
    GenerationConfig,
    LLMClient,
    MockLLMClient,
    OpenAICompatibleClient,
    audit_report,
    generate_report,
    load_cases,
)
from ..generation.audit import AuditResult
from ..retrieval import RetrievedChunk, Retriever
from .claims import Claim, ClaimExtractor, MockClaimExtractor
from .feature_verify import FeatureVerification, classify_feature_claim, verify_features
from .judge import JudgeClient, JudgeResult, MockJudgeClient
from .metrics import summarize_config

EVALUATION_DIR = Path(__file__).resolve().parent
CASES_DIR = EVALUATION_DIR / "cases"
RESULTS_DIR = EVALUATION_DIR / "results"
DEFAULT_CONFIGS = (GEN_NO_RAG, GEN_NAIVE_RAG, GEN_FULL_RAG, GEN_SELF_CHECK)
_CONFIG_BY_NAME = {config.name: config for config in DEFAULT_CONFIGS}


@dataclass(slots=True)
class _CaseEvaluation:
    config: GenerationConfig
    claims: list[Claim]
    verification: FeatureVerification
    judge_result: JudgeResult
    audit: AuditResult
    fallback: bool
    needs_review: bool


class _MemoizingRetriever:
    """Avoid duplicate local model work across equivalent evaluation queries."""

    def __init__(self, retriever: Retriever) -> None:
        self.inner = retriever
        self._cache: dict[tuple[Any, ...], list[RetrievedChunk]] = {}

    @property
    def records_by_id(self) -> dict[str, dict[str, Any]]:
        return self.inner.records_by_id

    def retrieve(self, section, attack_type, device_category, config):
        key = (section, attack_type, device_category, config)
        if key not in self._cache:
            self._cache[key] = self.inner.retrieve(
                section, attack_type, device_category, config
            )
        return list(self._cache[key])


def _resolve_configs(
    configs: Sequence[GenerationConfig | str] | None,
) -> list[GenerationConfig]:
    resolved: list[GenerationConfig] = []
    for config in configs or DEFAULT_CONFIGS:
        if isinstance(config, str):
            if config not in _CONFIG_BY_NAME:
                raise ValueError(f"unknown evaluation config: {config!r}")
            config = _CONFIG_BY_NAME[config]
        resolved.append(config)
    names = [config.name for config in resolved]
    if len(names) != len(set(names)):
        raise ValueError("evaluation config names must be unique")
    return sorted(resolved, key=lambda item: item.name)


def _chunks_seen_by_generator(
    chunk_ids_by_section: dict[str, list[str]], retriever: _MemoizingRetriever
) -> dict[str, list[RetrievedChunk]]:
    chunks: dict[str, list[RetrievedChunk]] = {}
    for section, chunk_ids in chunk_ids_by_section.items():
        section_chunks: list[RetrievedChunk] = []
        for chunk_id in chunk_ids:
            record = retriever.records_by_id[chunk_id]
            metadata = {
                key: value
                for key, value in record.items()
                if key not in {"chunk_id", "doc_id", "text"}
            }
            section_chunks.append(
                RetrievedChunk(
                    chunk_id=chunk_id,
                    doc_id=record["doc_id"],
                    score=0.0,
                    text=record["text"],
                    metadata=metadata,
                )
            )
        chunks[section] = section_chunks
    return chunks


def _write_csv(path: Path, rows: list[dict[str, Any]], fieldnames: list[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def run_eval(
    split: str = "dev",
    configs: Sequence[GenerationConfig | str] | None = None,
    generator_client: LLMClient | None = None,
    judge_client: JudgeClient | MockJudgeClient | None = None,
    claim_extractor: ClaimExtractor | MockClaimExtractor | None = None,
    retriever: Retriever | None = None,
    use_cache: bool = True,
) -> list[dict[str, Any]]:
    """Evaluate all requested configs and write the three protocol CSV artefacts."""

    if split not in ("dev", "frozen"):
        raise ValueError("split must be 'dev' or 'frozen'")
    if generator_client is None:
        generator_client = OpenAICompatibleClient()
    if judge_client is None:
        judge_client = JudgeClient()
    if claim_extractor is None:
        claim_extractor = ClaimExtractor(generator_client)

    active_configs = _resolve_configs(configs)
    needs_retrieval = any(config.retrieval != "none" for config in active_configs)
    active_retriever = _MemoizingRetriever(retriever or Retriever()) if needs_retrieval else None
    cases = sorted(
        load_cases(CASES_DIR / f"eval_cases_{split}.json"),
        key=lambda case: case.case_id,
    )

    evaluations: list[_CaseEvaluation] = []
    claim_rows: list[dict[str, Any]] = []
    audit_rows: list[dict[str, Any]] = []
    gate_names: set[str] = set()

    for case in cases:
        for config in active_configs:
            generated = generate_report(
                case,
                config,
                retriever=active_retriever,
                client=generator_client,
                use_cache=use_cache,
            )
            audit = audit_report(generated.report_md, case, generated.register)
            gate_names.update(audit.gate_results)
            claims = claim_extractor.extract(generated.report_md)
            verification = verify_features(
                generated.report_md,
                case,
                generated.chunk_ids_by_section,
            )

            judge_claims = [claim for claim in claims if claim.type != "feature"]
            chunks_by_section = (
                _chunks_seen_by_generator(
                    generated.chunk_ids_by_section, active_retriever
                )
                if generated.chunk_ids_by_section and active_retriever is not None
                else {}
            )
            judge_result = judge_client.judge(
                case,
                generated.report_md,
                judge_claims,
                chunks_by_section,
                config_name=config.name,
                use_cache=use_cache,
            )
            judged_labels = iter(judge_result.claim_labels)
            for claim in claims:
                if claim.type == "feature":
                    claim.label = classify_feature_claim(claim, verification)
                    verdict_source = "machine"
                else:
                    judged = next(judged_labels)
                    claim.label = judged["label"]
                    verdict_source = "judge"
                claim_rows.append(
                    {
                        "case_id": case.case_id,
                        "config": config.name,
                        "section": claim.section,
                        "type": claim.type,
                        "text": claim.text,
                        "cited_refs": json.dumps(claim.cited_refs),
                        "label": claim.label,
                        "verdict_source": verdict_source,
                    }
                )
            try:
                next(judged_labels)
            except StopIteration:
                pass
            else:
                raise RuntimeError("judge returned more labels than judge-routed claims")

            audit_rows.append(
                {
                    "case_id": case.case_id,
                    "config": config.name,
                    "register": generated.register,
                    **audit.gate_results,
                    "passed": audit.passed,
                    "needs_review": generated.needs_review,
                }
            )
            evaluations.append(
                _CaseEvaluation(
                    config=config,
                    claims=claims,
                    verification=verification,
                    judge_result=judge_result,
                    audit=audit,
                    fallback=generated.fallback,
                    needs_review=generated.needs_review,
                )
            )

    summary_rows: list[dict[str, Any]] = []
    for config in active_configs:
        selected = [item for item in evaluations if item.config.name == config.name]
        summary_rows.append(
            summarize_config(
                config.name,
                [
                    claim.label
                    for item in selected
                    for claim in item.claims
                    if claim.label is not None
                ],
                [item.verification for item in selected],
                [item.judge_result for item in selected],
                [item.audit for item in selected],
                [item.fallback for item in selected],
                [item.needs_review for item in selected],
            )
        )

    claim_rows.sort(key=lambda row: (row["case_id"], row["config"]))
    audit_rows.sort(key=lambda row: (row["case_id"], row["config"]))
    summary_rows.sort(key=lambda row: row["config"])
    summary_fields = list(summary_rows[0]) if summary_rows else ["config"]
    claim_fields = [
        "case_id",
        "config",
        "section",
        "type",
        "text",
        "cited_refs",
        "label",
        "verdict_source",
    ]
    audit_fields = [
        "case_id",
        "config",
        "register",
        *sorted(gate_names),
        "passed",
        "needs_review",
    ]
    _write_csv(RESULTS_DIR / f"eval_{split}_summary.csv", summary_rows, summary_fields)
    _write_csv(RESULTS_DIR / f"eval_{split}_claims.csv", claim_rows, claim_fields)
    _write_csv(RESULTS_DIR / f"rq2_audit_{split}.csv", audit_rows, audit_fields)
    return summary_rows


def _print_summary(rows: Sequence[dict[str, Any]]) -> None:
    columns = (
        ("config", "config"),
        ("n_cases", "cases"),
        ("total_claims", "claims"),
        ("hallucination_rate", "hallucination"),
        ("faithfulness", "faithfulness"),
        ("fabricated_number_rate", "fabricated_num"),
        ("invalid_ref_count", "invalid_refs"),
        ("contextual_misuse_count", "context_misuse"),
        ("all_gates_pass_rate", "all_gates"),
    )
    rendered: list[list[str]] = []
    for row in rows:
        rendered.append(
            [
                f"{row[key]:.4f}" if isinstance(row[key], float) else str(row[key])
                for key, _ in columns
            ]
        )
    widths = [
        max(len(label), *(len(row[index]) for row in rendered))
        for index, (_, label) in enumerate(columns)
    ]
    print("  ".join(label.ljust(width) for (_, label), width in zip(columns, widths)))
    print("  ".join("-" * width for width in widths))
    for row in rendered:
        print("  ".join(value.ljust(width) for value, width in zip(row, widths)))


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "frozen"), default="dev")
    parser.add_argument("--mock", action="store_true", help="use offline mock clients")
    parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args(argv)

    if args.mock:
        generator_client: LLMClient = MockLLMClient()
        judge_client: JudgeClient | MockJudgeClient = MockJudgeClient()
        extractor: ClaimExtractor | MockClaimExtractor = MockClaimExtractor()
    else:
        generator_client = OpenAICompatibleClient()
        judge_client = JudgeClient()
        extractor = ClaimExtractor(generator_client)
    rows = run_eval(
        split=args.split,
        generator_client=generator_client,
        judge_client=judge_client,
        claim_extractor=extractor,
        retriever=Retriever(),
        use_cache=not args.no_cache,
    )
    _print_summary(rows)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

