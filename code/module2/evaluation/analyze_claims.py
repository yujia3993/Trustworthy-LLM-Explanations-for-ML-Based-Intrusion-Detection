"""Deterministically summarize claim-level evaluation results.

This module intentionally uses only the Python standard library so that claim
analysis can run without importing any of the evaluation pipeline's ML
dependencies.
"""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Iterable, Sequence


LABELS = ("supported", "unsupported_but_true", "unsupported_and_false")
CLAIM_TYPES = ("feature", "knowledge", "procedural")
REQUIRED_COLUMNS = {
    "config",
    "section",
    "type",
    "cited_refs",
    "label",
}
CONFIG_COLUMNS = (
    "config",
    "n_claims",
    "supported",
    "unsupported_but_true",
    "unsupported_and_false",
    "faithfulness",
    "hallucination_rate",
    "ubt_feature",
    "ubt_knowledge_proc_uncited",
    "ubt_knowledge_proc_cited",
    "knowledge_proc_citation_rate",
    "n_feature",
    "n_knowledge",
    "n_procedural",
)
SECTION_COLUMNS = (
    "config",
    "section",
    "n_claims",
    "supported",
    "unsupported_but_true",
    "unsupported_and_false",
    "faithfulness",
)

RESULTS_DIR = Path(__file__).resolve().parent / "results"


class ClaimAnalysisError(ValueError):
    """Raised when claim analysis cannot safely produce correct results."""


def _new_counts() -> dict[str, int]:
    return {
        "n_claims": 0,
        "supported": 0,
        "unsupported_but_true": 0,
        "unsupported_and_false": 0,
        "ubt_feature": 0,
        "ubt_knowledge_proc_uncited": 0,
        "ubt_knowledge_proc_cited": 0,
        "knowledge_proc": 0,
        "knowledge_proc_cited": 0,
        "n_feature": 0,
        "n_knowledge": 0,
        "n_procedural": 0,
    }


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def _read_rows(claims_csv: Path) -> Iterable[tuple[int, dict[str, str], list[object]]]:
    try:
        csv_file = claims_csv.open(newline="", encoding="utf-8")
    except FileNotFoundError as exc:
        raise ClaimAnalysisError(f"Claims CSV does not exist: {claims_csv}") from exc
    except OSError as exc:
        raise ClaimAnalysisError(f"Could not read claims CSV {claims_csv}: {exc}") from exc

    with csv_file:
        reader = csv.DictReader(csv_file)
        if reader.fieldnames is None:
            raise ClaimAnalysisError(f"Claims CSV has no header row: {claims_csv}")
        missing = sorted(REQUIRED_COLUMNS.difference(reader.fieldnames))
        if missing:
            raise ClaimAnalysisError(
                f"Claims CSV {claims_csv} is missing required columns: "
                f"{', '.join(missing)}"
            )

        for row_number, row in enumerate(reader, start=2):
            label = row["label"]
            if label not in LABELS:
                raise ClaimAnalysisError(
                    f"Unknown label {label!r} at row {row_number} in {claims_csv}; "
                    f"expected one of {', '.join(LABELS)}"
                )

            claim_type = row["type"]
            if claim_type not in CLAIM_TYPES:
                raise ClaimAnalysisError(
                    f"Unknown claim type {claim_type!r} at row {row_number} in "
                    f"{claims_csv}; expected one of {', '.join(CLAIM_TYPES)}"
                )

            raw_refs = row["cited_refs"]
            try:
                cited_refs = json.loads(raw_refs)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ClaimAnalysisError(
                    f"Malformed cited_refs at row {row_number} in {claims_csv}: "
                    f"{raw_refs!r}"
                ) from exc
            if not isinstance(cited_refs, list):
                raise ClaimAnalysisError(
                    f"cited_refs must be a JSON list at row {row_number} in "
                    f"{claims_csv}: {raw_refs!r}"
                )

            yield row_number, row, cited_refs


def analyze_claims(
    claims_csv: str | Path,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Analyze a claims CSV and return config and config/section summaries."""

    input_path = Path(claims_csv)
    config_counts: dict[str, dict[str, int]] = defaultdict(_new_counts)
    section_counts: dict[tuple[str, str], dict[str, int]] = defaultdict(_new_counts)

    for _row_number, row, cited_refs in _read_rows(input_path):
        config = row["config"]
        section = row["section"]
        claim_type = row["type"]
        label = row["label"]
        has_citation = bool(cited_refs)

        counts = config_counts[config]
        per_section = section_counts[(config, section)]
        for target in (counts, per_section):
            target["n_claims"] += 1
            target[label] += 1

        counts[f"n_{claim_type}"] += 1
        if claim_type != "feature":
            counts["knowledge_proc"] += 1
            if has_citation:
                counts["knowledge_proc_cited"] += 1

        if label == "unsupported_but_true":
            if claim_type == "feature":
                counts["ubt_feature"] += 1
            elif has_citation:
                counts["ubt_knowledge_proc_cited"] += 1
            else:
                counts["ubt_knowledge_proc_uncited"] += 1

    config_rows: list[dict[str, object]] = []
    for config in sorted(config_counts):
        counts = config_counts[config]
        partition_total = (
            counts["ubt_feature"]
            + counts["ubt_knowledge_proc_uncited"]
            + counts["ubt_knowledge_proc_cited"]
        )
        if partition_total != counts["unsupported_but_true"]:
            raise ClaimAnalysisError(
                "unsupported_but_true partition mismatch for config "
                f"{config!r}: buckets total {partition_total}, but label count is "
                f"{counts['unsupported_but_true']}. The input schema may have changed."
            )

        config_rows.append(
            {
                "config": config,
                "n_claims": counts["n_claims"],
                "supported": counts["supported"],
                "unsupported_but_true": counts["unsupported_but_true"],
                "unsupported_and_false": counts["unsupported_and_false"],
                "faithfulness": _ratio(counts["supported"], counts["n_claims"]),
                "hallucination_rate": _ratio(
                    counts["unsupported_and_false"], counts["n_claims"]
                ),
                "ubt_feature": counts["ubt_feature"],
                "ubt_knowledge_proc_uncited": counts[
                    "ubt_knowledge_proc_uncited"
                ],
                "ubt_knowledge_proc_cited": counts["ubt_knowledge_proc_cited"],
                "knowledge_proc_citation_rate": _ratio(
                    counts["knowledge_proc_cited"], counts["knowledge_proc"]
                ),
                "n_feature": counts["n_feature"],
                "n_knowledge": counts["n_knowledge"],
                "n_procedural": counts["n_procedural"],
            }
        )

    section_rows: list[dict[str, object]] = []
    for config, section in sorted(section_counts):
        counts = section_counts[(config, section)]
        section_rows.append(
            {
                "config": config,
                "section": section,
                "n_claims": counts["n_claims"],
                "supported": counts["supported"],
                "unsupported_but_true": counts["unsupported_but_true"],
                "unsupported_and_false": counts["unsupported_and_false"],
                "faithfulness": _ratio(counts["supported"], counts["n_claims"]),
            }
        )

    return config_rows, section_rows


def _write_csv(
    output_path: Path,
    fieldnames: Sequence[str],
    rows: Iterable[dict[str, object]],
) -> None:
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
    except OSError as exc:
        raise ClaimAnalysisError(f"Could not write analysis CSV {output_path}: {exc}") from exc


def output_paths(out_prefix: str | Path) -> tuple[Path, Path]:
    """Return the config and by-section paths for an output prefix."""

    prefix = Path(out_prefix)
    return Path(f"{prefix}.csv"), Path(f"{prefix}_by_section.csv")


def run_analysis(
    claims_csv: str | Path, out_prefix: str | Path
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    """Analyze claims and write both output CSVs."""

    config_rows, section_rows = analyze_claims(claims_csv)
    config_output, section_output = output_paths(out_prefix)
    _write_csv(config_output, CONFIG_COLUMNS, config_rows)
    _write_csv(section_output, SECTION_COLUMNS, section_rows)
    return config_rows, section_rows


def format_summary(rows: Sequence[dict[str, object]]) -> str:
    """Format the headline decomposition as a readable stdout table."""

    headers = (
        "config",
        "claims",
        "supported",
        "ubt",
        "false",
        "faithfulness",
        "ubt feature",
        "ubt kp uncited",
        "ubt kp cited",
        "kp cite rate",
    )
    table_rows = [
        (
            str(row["config"]),
            str(row["n_claims"]),
            str(row["supported"]),
            str(row["unsupported_but_true"]),
            str(row["unsupported_and_false"]),
            f"{float(row['faithfulness']):.4f}",
            str(row["ubt_feature"]),
            str(row["ubt_knowledge_proc_uncited"]),
            str(row["ubt_knowledge_proc_cited"]),
            f"{float(row['knowledge_proc_citation_rate']):.4f}",
        )
        for row in rows
    ]
    widths = [
        max([len(headers[index]), *(len(row[index]) for row in table_rows)])
        for index in range(len(headers))
    ]

    def render(row: Sequence[str]) -> str:
        return "  ".join(value.ljust(widths[index]) for index, value in enumerate(row))

    lines = [render(headers), render(tuple("-" * width for width in widths))]
    lines.extend(render(row) for row in table_rows)
    return "\n".join(lines)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Decompose unsupported-but-true claims deterministically."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument(
        "--split",
        choices=("dev", "frozen"),
        help="Analyze evaluation/results/eval_<split>_claims.csv.",
    )
    source.add_argument("--claims-csv", type=Path, help="Path to an arbitrary claims CSV.")
    parser.add_argument(
        "--out-prefix",
        type=Path,
        help="Output path prefix (required with --claims-csv).",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.claims_csv is not None:
        if args.out_prefix is None:
            parser.error("--out-prefix is required when using --claims-csv")
        claims_csv = args.claims_csv
        out_prefix = args.out_prefix
    else:
        if args.out_prefix is not None:
            parser.error("--out-prefix can only be used with --claims-csv")
        claims_csv = RESULTS_DIR / f"eval_{args.split}_claims.csv"
        out_prefix = RESULTS_DIR / f"claim_analysis_{args.split}"

    try:
        config_rows, _section_rows = run_analysis(claims_csv, out_prefix)
    except ClaimAnalysisError as exc:
        parser.error(str(exc))

    config_output, section_output = output_paths(out_prefix)
    print(format_summary(config_rows))
    print(f"\nWrote {config_output}")
    print(f"Wrote {section_output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
