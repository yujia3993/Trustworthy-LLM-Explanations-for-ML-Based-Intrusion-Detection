"""Export the deterministic RQ3 human scoring sheet."""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path
from typing import Sequence

from ..generation import GEN_FULL_RAG, LLMClient, MockLLMClient, generate_report, load_cases
from ..retrieval import Retriever
from .claims import ClaimExtractor, MockClaimExtractor
from .judge import load_judge_rubric
from .run_eval import CASES_DIR, RESULTS_DIR, _MemoizingRetriever


def _select_case_ids(split: str, n: int) -> list[str]:
    raw_cases = json.loads(
        (CASES_DIR / f"eval_cases_{split}.json").read_text(encoding="utf-8")
    )
    if n > len(raw_cases):
        raise ValueError(f"requested {n} RQ3 cases but split contains {len(raw_cases)}")
    by_stratum: dict[str, list[str]] = {}
    for item in raw_cases:
        stratum = item.get("metadata", {}).get("stratum", "unknown")
        by_stratum.setdefault(stratum, []).append(item["case_id"])
    for case_ids in by_stratum.values():
        case_ids.sort()

    rubric = load_judge_rubric()["rq3"]
    rng = random.Random(42)
    selected: list[str] = []
    for stratum, minimum_key in (
        ("hedged_pair", "hedged_pair_min"),
        ("assertive_error", "assertive_error_min"),
    ):
        candidates = by_stratum.get(stratum, [])
        take = min(int(rubric["stratification"][minimum_key]), len(candidates), n - len(selected))
        selected.extend(rng.sample(candidates, take))
    remaining = sorted(
        item["case_id"] for item in raw_cases if item["case_id"] not in selected
    )
    selected.extend(rng.sample(remaining, n - len(selected)))
    return sorted(selected)


def export_rq3_sheet(
    split: str = "frozen",
    n: int = 20,
    out: str | Path = RESULTS_DIR / "rq3_scoring_sheet.csv",
    client: LLMClient | None = None,
    retriever: Retriever | None = None,
    claim_extractor: ClaimExtractor | MockClaimExtractor | None = None,
) -> Path:
    """Generate full-RAG reports and export blank human-rating columns."""

    if split not in ("dev", "frozen"):
        raise ValueError("split must be 'dev' or 'frozen'")
    if n <= 0:
        raise ValueError("n must be positive")
    client = client or MockLLMClient()
    claim_extractor = claim_extractor or MockClaimExtractor()
    active_retriever = _MemoizingRetriever(retriever or Retriever())
    selected_ids = set(_select_case_ids(split, n))
    cases = [
        case
        for case in load_cases(CASES_DIR / f"eval_cases_{split}.json")
        if case.case_id in selected_ids
    ]
    cases.sort(key=lambda case: case.case_id)

    generated_rows: list[tuple[str, str, int]] = []
    max_claims = 0
    for case in cases:
        generated = generate_report(
            case,
            GEN_FULL_RAG,
            retriever=active_retriever,
            client=client,
            use_cache=False,
        )
        claim_count = len(claim_extractor.extract(generated.report_md))
        max_claims = max(max_claims, claim_count)
        generated_rows.append((case.case_id, generated.report_md, claim_count))

    score_fields = list(load_judge_rubric()["report_scores"])
    claim_fields = [f"claim_{index}_label" for index in range(1, max_claims + 1)]
    fieldnames = ["case_id", "config", "report_md", *score_fields, *claim_fields]
    output_path = Path(out)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for case_id, report_md, _ in generated_rows:
            row = {field: "" for field in fieldnames}
            row.update(
                {"case_id": case_id, "config": GEN_FULL_RAG.name, "report_md": report_md}
            )
            writer.writerow(row)
    return output_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--split", choices=("dev", "frozen"), default="frozen")
    parser.add_argument("--n", type=int, default=20)
    parser.add_argument("--out", type=Path, default=RESULTS_DIR / "rq3_scoring_sheet.csv")
    parser.add_argument("--mock", action="store_true")
    args = parser.parse_args(argv)
    if not args.mock:
        raise SystemExit("only --mock is wired for CLI export; pass a real client in Python")
    path = export_rq3_sheet(args.split, args.n, args.out, MockLLMClient())
    print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

