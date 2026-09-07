"""Export and score the frozen RQ3 human-versus-judge agreement sample.

Export creates three CSV files and one human-readable Markdown file in ``out_dir``:

* ``rq3_scoring_sheet_reports.csv`` contains the exact cached reports shown to
  the judge and blank report-level cells for the human rater.
* ``rq3_scoring_sheet_claims.csv`` contains the exact non-feature claims routed
  to the judge, their cited references, and blank human labels.
  ``(case_id, claim_index)`` is the claim alignment key.
* ``rq3_judge_reference.csv`` is withheld from the rater. It has a ``kind``
  column: ``claim`` rows carry ``claim_index`` and ``judge_label``; ``report``
  rows carry the judge's factual-accuracy and actionability scores.
* ``rq3_case_materials.md`` contains the alert, evidence, and retrieved context
  blocks supplied to the judge, but no judge answers.

The scorer uses only these artifacts, rather than consulting cache internals.
"""

from __future__ import annotations

import argparse
import csv
import json
import random
import re
import sys
from pathlib import Path
from typing import Any, Sequence

from ..generation import (
    GEN_FULL_RAG,
    LLMClient,
    MockLLMClient,
    OpenAICompatibleClient,
    ReportCache,
    generate_report,
    load_cases,
)
from ..generation.cache import DEFAULT_CACHE_DIR
from ..generation.prompt_builder import _alert_data, _context_block, format_evidence
from ..retrieval import Retriever
from .claim_cache import ClaimCache, DEFAULT_CLAIM_CACHE_DIR
from .claims import ClaimExtractor, MockClaimExtractor
from .judge import JudgeClient, MockJudgeClient, load_judge_rubric
from .metrics import cohens_kappa, weighted_kappa
from .run_eval import (
    CASES_DIR,
    RESULTS_DIR,
    _chunks_seen_by_generator,
    _MemoizingRetriever,
)

REPORTS_FILENAME = "rq3_scoring_sheet_reports.csv"
CLAIMS_FILENAME = "rq3_scoring_sheet_claims.csv"
JUDGE_REFERENCE_FILENAME = "rq3_judge_reference.csv"
MATERIALS_FILENAME = "rq3_case_materials.md"
AGREEMENT_FILENAME = "rq3_agreement.csv"
_INTEGER_PATTERN = re.compile(r"-?(?:0|[1-9]\d*)")
_CLAIM_INDEX_PATTERN = re.compile(r"(?:0|[1-9]\d*)")


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


def _report_score_fields() -> list[str]:
    return [
        field
        for field in load_judge_rubric()["report_scores"]
        if field not in {"hallucination_check", "comments"}
    ]


def _write_csv(
    path: Path, rows: Sequence[dict[str, Any]], fieldnames: Sequence[str]
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _has_human_annotations(path: Path, human_fields: Sequence[str]) -> bool:
    if not path.exists():
        return False
    with path.open(encoding="utf-8", newline="") as handle:
        for row in csv.DictReader(handle):
            if any((row.get(field) or "").strip() for field in human_fields):
                return True
    return False


def _protect_human_annotations(
    reports_path: Path,
    claims_path: Path,
    score_fields: Sequence[str],
    *,
    force: bool,
) -> None:
    if force:
        return
    for path, human_fields in (
        (reports_path, score_fields),
        (claims_path, ("human_label",)),
    ):
        if _has_human_annotations(path, human_fields):
            raise FileExistsError(
                f"{path}: refusing to overwrite a sheet containing human "
                "annotations; --force will discard human annotations"
            )


def _case_material(case: Any, chunks_by_section: dict[str, list[Any]]) -> str:
    context = _context_block(chunks_by_section)
    return "\n\n".join(
        (
            f"## {case.case_id}",
            f"### ALERT DATA\n{_alert_data(case)}",
            f"### EVIDENCE\nEVIDENCE\n{format_evidence(case.evidence)}",
            f"### CONTEXT\n{context or '(no retrieved context)'}",
        )
    )


def _write_materials(path: Path, case_materials: Sequence[str]) -> None:
    header = (
        "# RQ3 Case Grounding Materials\n\n"
        "This is the grounding material the judge received for the selected RQ3 "
        "cases. It is provided so the human rater can apply the `supported` "
        "entailment criterion. It contains no judge answers."
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n\n".join((header, *case_materials)) + "\n", encoding="utf-8")


def _export_rq3_files(
    split: str,
    n: int,
    out_dir: str | Path,
    client: LLMClient | None,
    retriever: Retriever | None,
    claim_extractor: ClaimExtractor | MockClaimExtractor | None,
    use_cache: bool,
    judge_client: JudgeClient | MockJudgeClient | None,
    *,
    claims_only: bool,
    force: bool,
) -> tuple[Path, ...]:
    """Build either the complete export or only the rater-facing claim files."""

    if split not in ("dev", "frozen"):
        raise ValueError("split must be 'dev' or 'frozen'")
    if n <= 0:
        raise ValueError("n must be positive")

    output_dir = Path(out_dir)
    reports_path = output_dir / REPORTS_FILENAME
    claims_path = output_dir / CLAIMS_FILENAME
    reference_path = output_dir / JUDGE_REFERENCE_FILENAME
    materials_path = output_dir / MATERIALS_FILENAME
    score_fields = _report_score_fields()
    if not claims_only:
        _protect_human_annotations(
            reports_path, claims_path, score_fields, force=force
        )

    generator_client = client or OpenAICompatibleClient()
    active_judge = None if claims_only else (judge_client or JudgeClient())
    generation_cache = ReportCache(DEFAULT_CACHE_DIR)
    claim_cache = ClaimCache(DEFAULT_CLAIM_CACHE_DIR)
    if claim_extractor is None:
        active_extractor: ClaimExtractor | MockClaimExtractor = ClaimExtractor(
            generator_client, cache=claim_cache, use_cache=use_cache
        )
    elif isinstance(claim_extractor, ClaimExtractor):
        active_extractor = ClaimExtractor(
            claim_extractor.client, cache=claim_cache, use_cache=use_cache
        )
    else:
        active_extractor = claim_extractor

    active_retriever = _MemoizingRetriever(retriever or Retriever())
    selected_ids = set(_select_case_ids(split, n))
    cases = sorted(
        (
            case
            for case in load_cases(CASES_DIR / f"eval_cases_{split}.json")
            if case.case_id in selected_ids
        ),
        key=lambda case: case.case_id,
    )
    found_ids = {case.case_id for case in cases}
    if found_ids != selected_ids:
        missing = sorted(selected_ids - found_ids)
        raise ValueError(f"selected RQ3 cases were not loaded: {missing}")

    report_rows: list[dict[str, Any]] = []
    claim_rows: list[dict[str, Any]] = []
    reference_rows: list[dict[str, Any]] = []
    case_materials: list[str] = []
    for case in cases:
        generated = generate_report(
            case,
            GEN_FULL_RAG,
            retriever=active_retriever,
            client=generator_client,
            cache=generation_cache,
            use_cache=use_cache,
        )
        claims = active_extractor.extract(generated.report_md)
        judge_claims = [claim for claim in claims if claim.type != "feature"]
        chunks_by_section = _chunks_seen_by_generator(
            generated.chunk_ids_by_section, active_retriever
        )
        case_materials.append(_case_material(case, chunks_by_section))

        for claim_index, claim in enumerate(judge_claims):
            claim_rows.append(
                {
                    "case_id": case.case_id,
                    "claim_index": claim_index,
                    "section": claim.section,
                    "cited_refs": json.dumps(claim.cited_refs),
                    "claim_text": claim.text,
                    "human_label": "",
                }
            )

        if claims_only:
            continue

        assert active_judge is not None
        judge_result = active_judge.judge(
            case,
            generated.report_md,
            judge_claims,
            chunks_by_section,
            config_name=GEN_FULL_RAG.name,
            use_cache=use_cache,
        )
        if len(judge_claims) != len(judge_result.claim_labels):
            raise RuntimeError(
                f"RQ3 case {case.case_id!r}: {len(judge_claims)} judge-routed "
                f"claims but stored judge result has "
                f"{len(judge_result.claim_labels)} labels"
            )

        report_row = {"case_id": case.case_id, "report_md": generated.report_md}
        report_row.update({field: "" for field in score_fields})
        report_rows.append(report_row)

        report_reference: dict[str, Any] = {
            "kind": "report",
            "case_id": case.case_id,
            "claim_index": "",
            "judge_label": "",
        }
        report_reference.update(
            {field: getattr(judge_result, field) for field in score_fields}
        )
        reference_rows.append(report_reference)

        for claim_index, (claim, judged) in enumerate(
            zip(judge_claims, judge_result.claim_labels)
        ):
            if judged["text"] != claim.text:
                raise RuntimeError(
                    f"RQ3 claim alignment mismatch for "
                    f"{(case.case_id, claim_index)!r}: stored judge text differs "
                    "from the extracted claim"
                )
            claim_reference: dict[str, Any] = {
                "kind": "claim",
                "case_id": case.case_id,
                "claim_index": claim_index,
                "judge_label": judged["label"],
            }
            claim_reference.update({field: "" for field in score_fields})
            reference_rows.append(claim_reference)

    _write_csv(
        claims_path,
        claim_rows,
        [
            "case_id",
            "claim_index",
            "section",
            "cited_refs",
            "claim_text",
            "human_label",
        ],
    )
    _write_materials(materials_path, case_materials)
    if claims_only:
        return claims_path, materials_path

    _write_csv(
        reports_path,
        report_rows,
        ["case_id", "report_md", *score_fields],
    )
    _write_csv(
        reference_path,
        reference_rows,
        [
            "kind",
            "case_id",
            "claim_index",
            "judge_label",
            *score_fields,
        ],
    )
    return reports_path, claims_path, reference_path


def export_rq3_sheet(
    split: str = "frozen",
    n: int = 20,
    out_dir: str | Path = RESULTS_DIR,
    client: LLMClient | None = None,
    retriever: Retriever | None = None,
    claim_extractor: ClaimExtractor | MockClaimExtractor | None = None,
    use_cache: bool = True,
    judge_client: JudgeClient | MockJudgeClient | None = None,
    force: bool = False,
) -> tuple[Path, Path, Path]:
    """Export the exact reports, claims, and stored judge answers for RQ3."""

    paths = _export_rq3_files(
        split,
        n,
        out_dir,
        client,
        retriever,
        claim_extractor,
        use_cache,
        judge_client,
        claims_only=False,
        force=force,
    )
    return paths[0], paths[1], paths[2]


def refresh_rq3_claims(
    split: str = "frozen",
    n: int = 20,
    out_dir: str | Path = RESULTS_DIR,
    client: LLMClient | None = None,
    retriever: Retriever | None = None,
    claim_extractor: ClaimExtractor | MockClaimExtractor | None = None,
    use_cache: bool = True,
) -> tuple[Path, Path]:
    """Refresh only the claims sheet and human-readable grounding materials."""

    paths = _export_rq3_files(
        split,
        n,
        out_dir,
        client,
        retriever,
        claim_extractor,
        use_cache,
        None,
        claims_only=True,
        force=False,
    )
    return paths[0], paths[1]


def _read_csv(path: str | Path, required_fields: Sequence[str]) -> list[dict[str, str]]:
    csv_path = Path(path)
    with csv_path.open(encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        actual_fields = set(reader.fieldnames or ())
        missing_fields = [field for field in required_fields if field not in actual_fields]
        if missing_fields:
            raise ValueError(
                f"{csv_path}: missing required columns {missing_fields}"
            )
        return list(reader)


def _required_text(value: str | None, field: str, key: object) -> str:
    text = "" if value is None else value
    if not text.strip():
        raise ValueError(f"{key!r}: human field {field!r} is unfilled")
    return text


def _case_id(value: str | None, source: Path) -> str:
    case_id = "" if value is None else value
    if not case_id.strip():
        raise ValueError(f"{source}: row has an unfilled case_id alignment key")
    return case_id


def _claim_index(value: str | None, case_id: str, source: Path) -> int:
    text = "" if value is None else value
    key = (case_id, text)
    if not _CLAIM_INDEX_PATTERN.fullmatch(text):
        raise ValueError(f"{source}: claim alignment key {key!r} has invalid claim_index")
    return int(text)


def _rubric_integer(
    value: str | None,
    field: str,
    key: object,
    *,
    human: bool,
) -> int:
    text = "" if value is None else value
    owner = "human" if human else "judge reference"
    if not text.strip():
        raise ValueError(f"{key!r}: {owner} field {field!r} is unfilled")
    if not _INTEGER_PATTERN.fullmatch(text):
        raise ValueError(
            f"{key!r}: {owner} field {field!r} has non-integer value {text!r}"
        )
    number = int(text)
    rule = load_judge_rubric()["report_scores"][field]
    valid = (
        ("enum" not in rule or number in rule["enum"])
        and ("min" not in rule or number >= rule["min"])
        and ("max" not in rule or number <= rule["max"])
    )
    if not valid:
        if "enum" in rule:
            domain = list(rule["enum"])
        else:
            domain = f"{rule.get('min', '-infinity')}..{rule.get('max', 'infinity')}"
        raise ValueError(
            f"{key!r}: {owner} field {field!r} has out-of-domain value "
            f"{number!r}; expected {domain}"
        )
    return number


def _alignment_error(
    kind: str, human_keys: set[object], judge_keys: set[object]
) -> None:
    human_only = sorted(human_keys - judge_keys, key=repr)
    if human_only:
        raise ValueError(
            f"{kind} alignment key {human_only[0]!r} is present in the human "
            "sheet but missing from the judge reference"
        )
    judge_only = sorted(judge_keys - human_keys, key=repr)
    if judge_only:
        raise ValueError(
            f"{kind} alignment key {judge_only[0]!r} is present in the judge "
            "reference but missing from the human sheet"
        )


def score_rq3(
    reports_csv: str | Path,
    claims_csv: str | Path,
    judge_reference_csv: str | Path,
    out: str | Path = RESULTS_DIR / AGREEMENT_FILENAME,
) -> Path:
    """Validate, align, and score filled RQ3 sheets against the judge reference."""

    score_fields = _report_score_fields()
    allowed_labels = set(load_judge_rubric()["claim_labels"])
    reports_path = Path(reports_csv)
    claims_path = Path(claims_csv)
    reference_path = Path(judge_reference_csv)

    human_claims: dict[tuple[str, int], str] = {}
    for row in _read_csv(
        claims_path,
        ["case_id", "claim_index", "section", "claim_text", "human_label"],
    ):
        case_id = _case_id(row["case_id"], claims_path)
        index = _claim_index(row["claim_index"], case_id, claims_path)
        key = (case_id, index)
        if key in human_claims:
            raise ValueError(f"duplicate claim alignment key {key!r} in human sheet")
        label = _required_text(row["human_label"], "human_label", key)
        if label not in allowed_labels:
            raise ValueError(
                f"{key!r}: human_label has out-of-domain value {label!r}; "
                f"expected one of {sorted(allowed_labels)}"
            )
        human_claims[key] = label

    human_reports: dict[str, dict[str, int]] = {}
    for row in _read_csv(
        reports_path, ["case_id", "report_md", *score_fields]
    ):
        case_id = _case_id(row["case_id"], reports_path)
        if case_id in human_reports:
            raise ValueError(
                f"duplicate report alignment key {case_id!r} in human sheet"
            )
        human_reports[case_id] = {
            field: _rubric_integer(row[field], field, case_id, human=True)
            for field in score_fields
        }

    judge_claims: dict[tuple[str, int], str] = {}
    judge_reports: dict[str, dict[str, int]] = {}
    for row in _read_csv(
        reference_path,
        ["kind", "case_id", "claim_index", "judge_label", *score_fields],
    ):
        kind = row["kind"]
        case_id = _case_id(row["case_id"], reference_path)
        if kind == "claim":
            index = _claim_index(row["claim_index"], case_id, reference_path)
            key = (case_id, index)
            if key in judge_claims:
                raise ValueError(
                    f"duplicate claim alignment key {key!r} in judge reference"
                )
            label = row["judge_label"]
            if not label.strip():
                raise ValueError(
                    f"{key!r}: judge reference field 'judge_label' is unfilled"
                )
            if label not in allowed_labels:
                raise ValueError(
                    f"{key!r}: judge_label has out-of-domain value {label!r}; "
                    f"expected one of {sorted(allowed_labels)}"
                )
            judge_claims[key] = label
        elif kind == "report":
            if case_id in judge_reports:
                raise ValueError(
                    f"duplicate report alignment key {case_id!r} in judge reference"
                )
            judge_reports[case_id] = {
                field: _rubric_integer(row[field], field, case_id, human=False)
                for field in score_fields
            }
        else:
            raise ValueError(
                f"{reference_path}: case {case_id!r} has invalid kind {kind!r}; "
                "expected 'claim' or 'report'"
            )

    _alignment_error("claim", set(human_claims), set(judge_claims))
    _alignment_error("report", set(human_reports), set(judge_reports))
    if not human_claims:
        raise ValueError("claim sheets contain no aligned ratings")
    if not human_reports:
        raise ValueError("report sheets contain no aligned ratings")

    claim_keys = sorted(human_claims)
    report_keys = sorted(human_reports)
    rows: list[dict[str, Any]] = [
        {
            "metric": "claim_labels",
            "method": "cohens_kappa",
            "kappa": cohens_kappa(
                [human_claims[key] for key in claim_keys],
                [judge_claims[key] for key in claim_keys],
            ),
            "n": len(claim_keys),
        }
    ]
    for field in score_fields:
        human_values = [human_reports[key][field] for key in report_keys]
        judge_values = [judge_reports[key][field] for key in report_keys]
        if field == "factual_accuracy":
            method = "linear_weighted_kappa"
            coefficient = weighted_kappa(human_values, judge_values, "linear")
        else:
            method = "cohens_kappa"
            coefficient = cohens_kappa(human_values, judge_values)
        rows.append(
            {
                "metric": field,
                "method": method,
                "kappa": coefficient,
                "n": len(report_keys),
            }
        )

    output_path = Path(out)
    _write_csv(output_path, rows, ["metric", "method", "kappa", "n"])
    print("RQ3 human-vs-judge agreement")
    for row in rows:
        print(f"{row['metric']}: kappa={row['kappa']:.4f} (n={row['n']})")
    return output_path


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="mode", required=True)

    export_parser = subparsers.add_parser("export", help="export blank RQ3 sheets")
    export_parser.add_argument("--split", choices=("dev", "frozen"), default="frozen")
    export_parser.add_argument("--n", type=int, default=20)
    export_parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    export_parser.add_argument(
        "--mock", action="store_true", help="use offline mock clients"
    )
    export_parser.add_argument(
        "--force",
        action="store_true",
        help="discard any existing human annotations and overwrite the sheets",
    )

    refresh_parser = subparsers.add_parser(
        "refresh-claims",
        help="refresh only the claims sheet and rater grounding materials",
    )
    refresh_parser.add_argument(
        "--split", choices=("dev", "frozen"), default="frozen"
    )
    refresh_parser.add_argument("--n", type=int, default=20)
    refresh_parser.add_argument("--out-dir", type=Path, default=RESULTS_DIR)
    refresh_parser.add_argument(
        "--mock", action="store_true", help="use offline mock clients"
    )

    score_parser = subparsers.add_parser("score", help="score filled RQ3 sheets")
    score_parser.add_argument(
        "--reports", type=Path, default=RESULTS_DIR / REPORTS_FILENAME
    )
    score_parser.add_argument(
        "--claims", type=Path, default=RESULTS_DIR / CLAIMS_FILENAME
    )
    score_parser.add_argument(
        "--judge-reference",
        type=Path,
        default=RESULTS_DIR / JUDGE_REFERENCE_FILENAME,
    )
    score_parser.add_argument(
        "--out", type=Path, default=RESULTS_DIR / AGREEMENT_FILENAME
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if not arguments or arguments[0] not in {"export", "refresh-claims", "score"}:
        arguments.insert(0, "export")
    args = _parser().parse_args(arguments)

    if args.mode == "score":
        score_rq3(args.reports, args.claims, args.judge_reference, args.out)
        return 0

    if args.mock:
        generator_client: LLMClient = MockLLMClient()
        extractor: ClaimExtractor | MockClaimExtractor = MockClaimExtractor()
    else:
        generator_client = OpenAICompatibleClient()
        extractor = ClaimExtractor(generator_client)
    if args.mode == "refresh-claims":
        paths = refresh_rq3_claims(
            split=args.split,
            n=args.n,
            out_dir=args.out_dir,
            client=generator_client,
            retriever=Retriever(),
            claim_extractor=extractor,
            use_cache=True,
        )
    else:
        active_judge: JudgeClient | MockJudgeClient
        active_judge = MockJudgeClient() if args.mock else JudgeClient()
        paths = export_rq3_sheet(
            split=args.split,
            n=args.n,
            out_dir=args.out_dir,
            client=generator_client,
            retriever=Retriever(),
            claim_extractor=extractor,
            use_cache=True,
            judge_client=active_judge,
            force=args.force,
        )
    for path in paths:
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
