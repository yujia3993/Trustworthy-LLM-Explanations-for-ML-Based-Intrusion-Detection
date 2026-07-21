"""Export the frozen and development evaluation case sets.

``sampling_plan.md`` v1.0.0 is the design authority for this module.  The JSON
files are arrays so that :func:`module2.generation.cases.load_cases` can load
them directly.  Version information and the sampling-plan metadata are stored
as extra fields on each array element; ``AlertCase.from_dict`` deliberately
ignores those fields when reconstructing generation-layer cases.
"""

from __future__ import annotations

import json
import math
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Literal

import numpy as np
import pandas as pd

from ..config import AMBIGUOUS_PAIR, CLASS_ORDER, REGISTER_THRESHOLD
from ..generation.cases import AlertCase, EvidenceItem
from ..generation.registers import select_register
from ..kb_loader import load_metadata_schema

SAMPLING_SEED = 42
CASE_SET_VERSION = "1.0.0"
SAMPLING_PLAN_VERSION = "sampling_plan.md v1.0.0"
TOP_K_EVIDENCE = 5

MODULE2_DIR = Path(__file__).resolve().parents[1]
CODE_DIR = MODULE2_DIR.parent
RESULTS_DIR = CODE_DIR / "results"
MODELS_DIR = CODE_DIR / "models"
DATA_PATH = CODE_DIR / "nbaiot_sampled.parquet"
ALERTS_PATH = RESULTS_DIR / "alerts_full.parquet"
CASES_DIR = Path(__file__).resolve().parent / "cases"
FROZEN_PATH = CASES_DIR / "eval_cases_frozen.json"
DEV_PATH = CASES_DIR / "eval_cases_dev.json"
SPLIT_CHECK_PATH = RESULTS_DIR / "stage_b_reconstructed_split_check_clean_model.json"

NON_PAIR_ATTACK_CLASSES = tuple(
    class_name
    for class_name in CLASS_ORDER
    if class_name not in {"benign", *AMBIGUOUS_PAIR}
)

REQUIRED_SAMPLING_COLUMNS = frozenset(
    {
        "sample_id",
        "device_name",
        "y_pred",
        "top2_class",
        "margin",
        "label_type",
    }
)


@dataclass(frozen=True)
class SampledCaseSets:
    """Selected alert rows before evidence generation."""

    frozen: pd.DataFrame
    dev: pd.DataFrame


@dataclass(frozen=True)
class EvidenceMapping:
    """Evidence items and drop accounting for one case."""

    items: list[EvidenceItem]
    nan_median_dropped: int


def _is_pair_top2(frame: pd.DataFrame) -> pd.Series:
    """Whether the unordered top-two classes are exactly the ambiguous pair."""

    return (
        frame["y_pred"].isin(AMBIGUOUS_PAIR)
        & frame["top2_class"].isin(AMBIGUOUS_PAIR)
        & frame["y_pred"].ne(frame["top2_class"])
    )


def _sorted_pool(frame: pd.DataFrame) -> pd.DataFrame:
    return frame.sort_values("sample_id", kind="stable").reset_index(drop=True)


def _round_robin_by_device(frame: pd.DataFrame, n: int) -> pd.DataFrame:
    """Take lowest IDs in alphabetical-device round-robin order."""

    pool = _sorted_pool(frame)
    if n < 0:
        raise ValueError("sample size must be non-negative")
    if len(pool) < n:
        raise ValueError(f"candidate pool has {len(pool)} rows but {n} are required")
    if n == 0:
        return pool.iloc[0:0].copy()

    by_device = {
        str(device): group.reset_index(drop=True)
        for device, group in pool.groupby("device_name", sort=True)
    }
    positions = {device: 0 for device in by_device}
    selected: list[pd.Series] = []
    while len(selected) < n:
        made_progress = False
        for device in sorted(by_device):
            position = positions[device]
            group = by_device[device]
            if position >= len(group):
                continue
            selected.append(group.iloc[position])
            positions[device] += 1
            made_progress = True
            if len(selected) == n:
                break
        if not made_progress:  # pragma: no cover - guarded by the size check
            raise RuntimeError("round-robin selection exhausted unexpectedly")
    return pd.DataFrame(selected).reset_index(drop=True)


def _tag(frame: pd.DataFrame, stratum: str) -> pd.DataFrame:
    tagged = frame.copy()
    tagged["stratum"] = stratum
    return tagged


def _concat_tagged(parts: Iterable[pd.DataFrame]) -> pd.DataFrame:
    materialized = list(parts)
    if not materialized:
        return pd.DataFrame()
    return pd.concat(materialized, ignore_index=True)


def sample_case_sets(
    alerts: pd.DataFrame,
    *,
    seed: int = SAMPLING_SEED,
) -> SampledCaseSets:
    """Apply the frozen v1 strata and deterministic selection rules.

    The v1 design fixes seed 42.  Selection itself is fully resolved by the
    lower-sample-ID and alphabetical-device rules, so no random draw remains.
    Retaining the seed argument makes accidental use of another design seed an
    explicit error.
    """

    if seed != SAMPLING_SEED:
        raise ValueError(f"sampling_plan.md v1 fixes seed={SAMPLING_SEED}")
    missing = sorted(REQUIRED_SAMPLING_COLUMNS - set(alerts.columns))
    if missing:
        raise ValueError(f"sampling input is missing columns: {missing}")
    if alerts["sample_id"].duplicated().any():
        raise ValueError("sampling input contains duplicate sample_id values")

    population = _sorted_pool(alerts)
    pair_top2 = _is_pair_top2(population)
    assertive = population["margin"].ge(REGISTER_THRESHOLD)

    assertive_correct_pool = _sorted_pool(
        population[
            assertive
            & population["y_pred"].eq(population["label_type"])
            & ~pair_top2
        ]
    )
    assertive_error_pool = _sorted_pool(
        population[assertive & population["y_pred"].ne(population["label_type"])]
    )
    hedged_pair_pool = _sorted_pool(population[~assertive & pair_top2])
    hedged_generic_pool = _sorted_pool(population[~assertive & ~pair_top2])

    frozen_parts: list[pd.DataFrame] = []
    for class_name in NON_PAIR_ATTACK_CLASSES:
        class_pool = assertive_correct_pool[
            assertive_correct_pool["label_type"].eq(class_name)
        ]
        frozen_parts.append(
            _tag(_round_robin_by_device(class_pool, 7), "assertive_correct")
        )

    # "All, cap N" strata retain the lowest sample IDs from their sorted pools.
    frozen_parts.append(_tag(assertive_error_pool.head(5), "assertive_error"))
    for truth_member in AMBIGUOUS_PAIR:
        member_pool = hedged_pair_pool[
            hedged_pair_pool["label_type"].eq(truth_member)
        ]
        frozen_parts.append(
            _tag(_round_robin_by_device(member_pool, 18), "hedged_pair")
        )
    frozen_parts.append(_tag(hedged_generic_pool.head(6), "hedged_generic"))
    frozen = _concat_tagged(frozen_parts)

    # Structural disjointness: remove all frozen IDs from every source pool
    # before taking any development examples.
    frozen_ids = set(frozen["sample_id"].astype(int))
    remaining_correct = assertive_correct_pool[
        ~assertive_correct_pool["sample_id"].isin(frozen_ids)
    ]
    remaining_pair = hedged_pair_pool[
        ~hedged_pair_pool["sample_id"].isin(frozen_ids)
    ]

    dev_parts: list[pd.DataFrame] = []
    for class_name in NON_PAIR_ATTACK_CLASSES:
        class_pool = remaining_correct[remaining_correct["label_type"].eq(class_name)]
        dev_parts.append(
            _tag(_round_robin_by_device(class_pool, 1), "assertive_correct")
        )
    for truth_member in AMBIGUOUS_PAIR:
        member_pool = remaining_pair[remaining_pair["label_type"].eq(truth_member)]
        dev_parts.append(_tag(_round_robin_by_device(member_pool, 2), "hedged_pair"))
    dev = _concat_tagged(dev_parts)

    if frozen_ids & set(dev["sample_id"].astype(int)):
        raise AssertionError("frozen and dev sample IDs are not disjoint")
    return SampledCaseSets(frozen=frozen, dev=dev)


def evidence_screen(
    *,
    direction: str,
    z_score_vs_benign: float,
    actual_value: float,
    benign_p99: float,
    is_ambiguous_pair: bool,
) -> Literal["discriminative", "contextual"]:
    """Apply the sampling plan's v1 evidence-screen rule."""

    supports = direction == "supports_pred_class"
    outside_envelope = (
        z_score_vs_benign >= 3 or actual_value > benign_p99
    )
    if supports and outside_envelope and not is_ambiguous_pair:
        return "discriminative"
    return "contextual"


def map_evidence(
    top_feature_families: Iterable[dict[str, Any]],
    *,
    is_ambiguous_pair: bool,
) -> EvidenceMapping:
    """Convert Module 1 family explanations to generation evidence items."""

    items: list[EvidenceItem] = []
    dropped = 0
    for family in top_feature_families:
        reference = family["benign_reference"]
        median = float(reference["median"])
        if math.isnan(median):
            dropped += 1
            continue
        actual = float(family["actual_value"])
        std = float(reference["std"])
        p99 = float(reference["p99"])
        z_score = float(reference["z_score_vs_benign"])
        items.append(
            EvidenceItem(
                feature=str(family["representative_feature"]),
                value=round(actual, 10),
                benign_median=round(median, 10),
                benign_std=round(std, 10),
                benign_p99=round(p99, 10),
                screen=evidence_screen(
                    direction=str(family["direction"]),
                    z_score_vs_benign=z_score,
                    actual_value=actual,
                    benign_p99=p99,
                    is_ambiguous_pair=is_ambiguous_pair,
                ),
            )
        )
    return EvidenceMapping(items=items, nan_median_dropped=dropped)


def _validate_reconstructed_split(
    split_indices: dict[str, np.ndarray],
    n_rows: int,
) -> None:
    expected_keys = {"train", "calib", "test"}
    if set(split_indices) != expected_keys:
        raise AssertionError(f"unexpected reconstructed split keys: {set(split_indices)}")
    split_sets = {
        name: set(np.asarray(indices, dtype=int).tolist())
        for name, indices in split_indices.items()
    }
    for left, right in (("train", "calib"), ("train", "test"), ("calib", "test")):
        if split_sets[left] & split_sets[right]:
            raise AssertionError(f"reconstructed {left}/{right} indices overlap")
    union = set().union(*split_sets.values())
    if union != set(range(n_rows)):
        raise AssertionError("reconstructed splits do not cover the full dataset")
    observed_test_fraction = len(split_sets["test"]) / n_rows
    if not math.isclose(observed_test_fraction, 0.20, abs_tol=1 / n_rows):
        raise AssertionError(
            f"unexpected test fraction: {observed_test_fraction:.12f}"
        )

    if not SPLIT_CHECK_PATH.exists():
        raise FileNotFoundError(f"missing split verification: {SPLIT_CHECK_PATH}")
    check = json.loads(SPLIT_CHECK_PATH.read_text(encoding="utf-8"))
    if not check.get("matches_saved_report", False):
        raise AssertionError("saved clean-model reconstructed split check is not valid")
    if int(check["n_test"]) != len(split_sets["test"]):
        raise AssertionError("reconstructed test size disagrees with saved split check")
    if not math.isclose(float(check["test_fraction"]), 0.20, abs_tol=0.0):
        raise AssertionError("saved split check does not use the frozen 20% test fraction")
    if int(check["random_state"]) != SAMPLING_SEED:
        raise AssertionError("saved split check does not use random_state 42")


def _load_population(explainer: Any) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Load and join canonical alerts restricted to the rebuilt test split."""

    from module1_exports import reconstruct_stage_b_split_indices

    features = pd.read_parquet(DATA_PATH)
    alerts = pd.read_parquet(ALERTS_PATH)
    if not features.index.equals(pd.RangeIndex(len(features))):
        raise AssertionError("source feature table must use its positional RangeIndex")
    split_indices = reconstruct_stage_b_split_indices(features, explainer.label_encoder)
    _validate_reconstructed_split(split_indices, len(features))

    sample_ids = alerts["sample_id"].astype(int)
    if sample_ids.duplicated().any():
        raise AssertionError("alerts_full contains duplicate sample IDs")
    if not sample_ids.between(0, len(features) - 1).all():
        raise AssertionError("alerts_full sample IDs are outside the feature table")

    test_ids = set(np.asarray(split_indices["test"], dtype=int).tolist())
    population = alerts[sample_ids.isin(test_ids)].copy()
    population = _sorted_pool(population)
    joined = features.loc[population["sample_id"].astype(int)]
    if not np.array_equal(
        population["device_name"].to_numpy(), joined["device_name"].to_numpy()
    ):
        raise AssertionError("alerts_full device names disagree with source rows")
    if not joined["label_binary"].eq(1).all():
        raise AssertionError("held-out alert population contains benign source rows")
    population["label_type"] = joined["label_type"].to_numpy()
    return population, features


def _build_case(
    row: pd.Series,
    features: pd.DataFrame,
    explainer: Any,
    device_category_map: dict[str, str],
) -> tuple[AlertCase, float, int]:
    sample_id = int(row["sample_id"])
    source_row = features.loc[[sample_id]].copy()
    source_row["sample_id"] = sample_id
    explanation = explainer.explain_alert(
        source_row,
        str(row["y_pred"]),
        top_k=TOP_K_EVIDENCE,
    )
    pair_alert = {str(row["y_pred"]), str(row["top2_class"])} == set(AMBIGUOUS_PAIR)
    mapped = map_evidence(
        explanation["top_feature_families"],
        is_ambiguous_pair=pair_alert,
    )
    device_name = str(row["device_name"])
    try:
        device_category = device_category_map[device_name]
    except KeyError as exc:
        raise KeyError(f"no device category mapping for {device_name!r}") from exc

    case = AlertCase(
        case_id=f"{row['stratum']}-{sample_id}",
        device_name=device_name,
        device_category=device_category,
        y_pred=str(row["y_pred"]),
        p_top1=float(row["p_top1"]),
        top2_class=str(row["top2_class"]),
        p_top2=float(row["p_top2"]),
        p_pair=float(row["p_pair"]),
        margin=float(row["margin"]),
        entropy=float(row["entropy"]),
        evidence=mapped.items,
        label_type=str(row["label_type"]),
    )
    return (
        case,
        round(float(explanation["atypicality_score"]), 10),
        mapped.nan_median_dropped,
    )


def _case_record(
    case: AlertCase,
    row: pd.Series,
    atypicality_score: float,
    split: Literal["frozen", "dev"],
) -> dict[str, Any]:
    record = case.to_dict()
    record.update(
        {
            "case_set_version": CASE_SET_VERSION,
            "sampling_plan": SAMPLING_PLAN_VERSION,
            "metadata": {
                "atypicality_score": atypicality_score,
                "label_type": str(row["label_type"]),
                "sample_id": int(row["sample_id"]),
                "split": split,
                "stage_a_flagged": bool(row["stage_a_flagged"]),
                "stratum": str(row["stratum"]),
            },
        }
    )
    return record


def _materialize_records(
    selected: pd.DataFrame,
    *,
    split: Literal["frozen", "dev"],
    features: pd.DataFrame,
    explainer: Any,
    device_category_map: dict[str, str],
) -> tuple[list[dict[str, Any]], list[AlertCase], int, int]:
    records: list[dict[str, Any]] = []
    cases: list[AlertCase] = []
    dropped = 0
    empty_evidence = 0
    for _, row in selected.iterrows():
        case, atypicality, case_dropped = _build_case(
            row, features, explainer, device_category_map
        )
        cases.append(case)
        records.append(_case_record(case, row, atypicality, split))
        dropped += case_dropped
        empty_evidence += not case.evidence
    return records, cases, dropped, empty_evidence


def _write_records(records: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        records,
        indent=2,
        sort_keys=True,
        allow_nan=False,
    ) + "\n"
    path.write_text(payload, encoding="utf-8")


def _composition_summary(
    frozen_rows: pd.DataFrame,
    dev_rows: pd.DataFrame,
    frozen_cases: list[AlertCase],
    dev_cases: list[AlertCase],
    *,
    nan_median_dropped: int,
    empty_evidence_cases: int,
) -> dict[str, Any]:
    all_cases = frozen_cases + dev_cases
    screen_counts = Counter(
        item.screen for case in all_cases for item in case.evidence
    )
    return {
        "device_coverage": {
            "dev": sorted(dev_rows["device_name"].unique().tolist()),
            "frozen": sorted(frozen_rows["device_name"].unique().tolist()),
        },
        "empty_evidence_cases": empty_evidence_cases,
        "evidence_nan_median_dropped": nan_median_dropped,
        "evidence_screen_counts": dict(sorted(screen_counts.items())),
        "register_distribution": {
            "dev": dict(sorted(Counter(map(select_register, dev_cases)).items())),
            "frozen": dict(sorted(Counter(map(select_register, frozen_cases)).items())),
        },
        "stratum_counts": {
            "dev": dict(sorted(Counter(dev_rows["stratum"]).items())),
            "frozen": dict(sorted(Counter(frozen_rows["stratum"]).items())),
        },
    }


def export_case_sets() -> dict[str, Any]:
    """Create both evaluation files and return their composition summary."""

    from module1_exports import Module1Explainer

    explainer = Module1Explainer.from_artifacts(
        models_dir=MODELS_DIR,
        results_dir=RESULTS_DIR,
    )
    population, features = _load_population(explainer)
    selected = sample_case_sets(population)
    device_category_map = load_metadata_schema()["device_category_map"]

    frozen_records, frozen_cases, frozen_dropped, frozen_empty = _materialize_records(
        selected.frozen,
        split="frozen",
        features=features,
        explainer=explainer,
        device_category_map=device_category_map,
    )
    dev_records, dev_cases, dev_dropped, dev_empty = _materialize_records(
        selected.dev,
        split="dev",
        features=features,
        explainer=explainer,
        device_category_map=device_category_map,
    )
    _write_records(frozen_records, FROZEN_PATH)
    _write_records(dev_records, DEV_PATH)

    return _composition_summary(
        selected.frozen,
        selected.dev,
        frozen_cases,
        dev_cases,
        nan_median_dropped=frozen_dropped + dev_dropped,
        empty_evidence_cases=frozen_empty + dev_empty,
    )


def main() -> None:
    summary = export_case_sets()
    print(json.dumps(summary, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
