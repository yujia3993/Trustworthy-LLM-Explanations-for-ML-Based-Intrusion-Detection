import csv
from pathlib import Path

import pytest

from module2.evaluation import analyze_claims


EVALUATION_DIR = Path(__file__).resolve().parents[1] / "evaluation"
DEV_CLAIMS = EVALUATION_DIR / "results" / "eval_dev_claims.csv"
DEV_SUMMARY = EVALUATION_DIR / "results" / "eval_dev_summary.csv"

EXPECTED_DECOMPOSITION = {
    "no_rag": (454, 287, 29, 258, 0),
    "naive_rag": (456, 90, 24, 58, 8),
    "full_rag": (483, 90, 21, 60, 9),
    "self_check": (480, 89, 14, 46, 29),
}


def _rows_by_config(rows):
    return {row["config"]: row for row in rows}


def _write_claims_csv(path, *, label="supported", cited_refs="[]"):
    with path.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=(
                "case_id",
                "config",
                "section",
                "type",
                "text",
                "cited_refs",
                "label",
                "verdict_source",
            ),
        )
        writer.writeheader()
        writer.writerow(
            {
                "case_id": "synthetic",
                "config": "test_config",
                "section": "summary",
                "type": "knowledge",
                "text": "Synthetic claim",
                "cited_refs": cited_refs,
                "label": label,
                "verdict_source": "test",
            }
        )


def test_dev_claim_decomposition_and_outputs(tmp_path):
    out_prefix = tmp_path / "claim_analysis_dev"
    config_rows, section_rows = analyze_claims.run_analysis(DEV_CLAIMS, out_prefix)
    by_config = _rows_by_config(config_rows)

    assert [row["config"] for row in config_rows] == sorted(EXPECTED_DECOMPOSITION)
    for config, expected in EXPECTED_DECOMPOSITION.items():
        row = by_config[config]
        actual = (
            row["n_claims"],
            row["unsupported_but_true"],
            row["ubt_feature"],
            row["ubt_knowledge_proc_uncited"],
            row["ubt_knowledge_proc_cited"],
        )
        assert actual == expected
        assert (
            row["ubt_feature"]
            + row["ubt_knowledge_proc_uncited"]
            + row["ubt_knowledge_proc_cited"]
            == row["unsupported_but_true"]
        )

    assert round(by_config["full_rag"]["knowledge_proc_citation_rate"], 2) == 0.59
    assert round(by_config["self_check"]["knowledge_proc_citation_rate"], 2) == 0.72
    assert round(by_config["no_rag"]["knowledge_proc_citation_rate"], 2) == 0.13

    assert (tmp_path / "claim_analysis_dev.csv").is_file()
    assert (tmp_path / "claim_analysis_dev_by_section.csv").is_file()
    assert section_rows == sorted(
        section_rows, key=lambda row: (row["config"], row["section"])
    )
    for row in section_rows:
        assert (
            row["supported"]
            + row["unsupported_but_true"]
            + row["unsupported_and_false"]
            == row["n_claims"]
        )
        assert row["faithfulness"] == row["supported"] / row["n_claims"]
    for config, config_row in by_config.items():
        config_sections = [row for row in section_rows if row["config"] == config]
        for column in (
            "n_claims",
            "supported",
            "unsupported_but_true",
            "unsupported_and_false",
        ):
            assert sum(row[column] for row in config_sections) == config_row[column]

    with (tmp_path / "claim_analysis_dev.csv").open(
        newline="", encoding="utf-8"
    ) as csv_file:
        assert tuple(csv.DictReader(csv_file).fieldnames) == analyze_claims.CONFIG_COLUMNS
    with (tmp_path / "claim_analysis_dev_by_section.csv").open(
        newline="", encoding="utf-8"
    ) as csv_file:
        assert tuple(csv.DictReader(csv_file).fieldnames) == analyze_claims.SECTION_COLUMNS


def test_faithfulness_matches_independent_dev_summary():
    config_rows, _section_rows = analyze_claims.analyze_claims(DEV_CLAIMS)
    actual = {
        row["config"]: round(row["faithfulness"], 4) for row in config_rows
    }
    with DEV_SUMMARY.open(newline="", encoding="utf-8") as csv_file:
        expected = {
            row["config"]: round(float(row["faithfulness"]), 4)
            for row in csv.DictReader(csv_file)
        }

    assert actual == expected


def test_unknown_label_is_a_clear_error(tmp_path):
    claims_csv = tmp_path / "unknown_label.csv"
    _write_claims_csv(claims_csv, label="mostly_true")

    with pytest.raises(
        analyze_claims.ClaimAnalysisError, match=r"Unknown label.*row 2.*unknown_label\.csv"
    ):
        analyze_claims.analyze_claims(claims_csv)


def test_malformed_cited_refs_is_a_clear_error(tmp_path):
    claims_csv = tmp_path / "malformed_refs.csv"
    _write_claims_csv(claims_csv, cited_refs="[not valid JSON")

    with pytest.raises(
        analyze_claims.ClaimAnalysisError,
        match=r"Malformed cited_refs.*row 2.*malformed_refs\.csv",
    ):
        analyze_claims.analyze_claims(claims_csv)


def test_missing_input_is_a_clear_cli_error(tmp_path, capsys):
    missing_csv = tmp_path / "does_not_exist.csv"

    with pytest.raises(SystemExit) as exc_info:
        analyze_claims.main(
            [
                "--claims-csv",
                str(missing_csv),
                "--out-prefix",
                str(tmp_path / "unused"),
            ]
        )

    captured = capsys.readouterr()
    assert exc_info.value.code == 2
    assert str(missing_csv) in captured.err
    assert "does not exist" in captured.err
    assert "Traceback" not in captured.err
