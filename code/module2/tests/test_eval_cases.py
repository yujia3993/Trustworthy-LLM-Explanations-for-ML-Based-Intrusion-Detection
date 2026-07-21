"""Tests for the frozen Module 3 evaluation case-set exporter."""

from __future__ import annotations

import json
import math
from collections import Counter
from pathlib import Path

import pandas as pd
import pytest

from ..config import AMBIGUOUS_PAIR
from ..evaluation.export_cases import evidence_screen, map_evidence, sample_case_sets
from ..generation.cases import load_cases
from ..generation.registers import select_register


NON_PAIR_CLASSES = (
    "gafgyt_combo",
    "gafgyt_junk",
    "gafgyt_scan",
    "mirai_ack",
    "mirai_scan",
    "mirai_syn",
    "mirai_udp",
    "mirai_udpplain",
)


def _synthetic_alerts() -> pd.DataFrame:
    rows: list[dict] = []
    sample_id = 1000
    devices = ["device-d", "device-b", "device-a", "device-c"]

    def add(
        *,
        device_name: str,
        y_pred: str,
        top2_class: str,
        margin: float,
        label_type: str,
    ) -> None:
        nonlocal sample_id
        rows.append(
            {
                "sample_id": sample_id,
                "device_name": device_name,
                "y_pred": y_pred,
                "top2_class": top2_class,
                "margin": margin,
                "label_type": label_type,
            }
        )
        sample_id += 1

    # Fifteen candidates per class leave room for both frozen and dev draws.
    for class_name in NON_PAIR_CLASSES:
        for index in range(15):
            add(
                device_name=devices[index % len(devices)],
                y_pred=class_name,
                top2_class="benign",
                margin=0.95,
                label_type=class_name,
            )

    for truth_member in AMBIGUOUS_PAIR:
        other = next(member for member in AMBIGUOUS_PAIR if member != truth_member)
        for index in range(25):
            add(
                device_name=devices[index % len(devices)],
                y_pred=truth_member if index % 2 == 0 else other,
                top2_class=other if index % 2 == 0 else truth_member,
                margin=0.20,
                label_type=truth_member,
            )

    for index in range(6):
        add(
            device_name=devices[index % len(devices)],
            y_pred="gafgyt_combo",
            top2_class="benign",
            margin=0.95,
            label_type="gafgyt_junk",
        )
    for index in range(8):
        add(
            device_name=devices[index % len(devices)],
            y_pred="gafgyt_combo",
            top2_class="gafgyt_junk",
            margin=0.20,
            label_type="gafgyt_combo",
        )
    return pd.DataFrame(rows)


def test_sampling_is_deterministic_and_matches_frozen_sizes() -> None:
    alerts = _synthetic_alerts()
    first = sample_case_sets(alerts)
    second = sample_case_sets(alerts.sample(frac=1.0, random_state=7))

    assert first.frozen.to_dict("records") == second.frozen.to_dict("records")
    assert first.dev.to_dict("records") == second.dev.to_dict("records")

    counts = Counter(first.frozen["stratum"])
    assert counts["assertive_correct"] == 56
    assert counts["assertive_error"] <= 5
    assert counts["hedged_pair"] == 36
    assert counts["hedged_generic"] <= 6
    pair_truth = Counter(
        first.frozen.loc[
            first.frozen["stratum"].eq("hedged_pair"), "label_type"
        ]
    )
    assert pair_truth == {"gafgyt_tcp": 18, "gafgyt_udp": 18}


def test_dev_is_twelve_and_structurally_disjoint_from_frozen() -> None:
    sampled = sample_case_sets(_synthetic_alerts())
    assert len(sampled.dev) == 12
    assert Counter(sampled.dev["stratum"]) == {
        "assertive_correct": 8,
        "hedged_pair": 4,
    }
    assert set(sampled.frozen["sample_id"]).isdisjoint(sampled.dev["sample_id"])


def test_round_robin_spreads_each_class_across_devices() -> None:
    sampled = sample_case_sets(_synthetic_alerts())
    spread_rows = sampled.frozen[
        sampled.frozen["stratum"].isin({"assertive_correct", "hedged_pair"})
    ]
    for (_, _), group in spread_rows.groupby(["stratum", "label_type"]):
        available_devices = _synthetic_alerts().loc[
            _synthetic_alerts()["label_type"].eq(group["label_type"].iloc[0]),
            "device_name",
        ].nunique()
        max_allowed = math.ceil(len(group) / available_devices) + 1
        assert group.groupby("device_name").size().max() <= max_allowed
        assert group["device_name"].nunique() == available_devices


@pytest.mark.parametrize(
    (
        "direction",
        "z_score",
        "actual",
        "p99",
        "ambiguous",
        "expected",
    ),
    [
        ("supports_pred_class", 3.0, 8.0, 10.0, False, "discriminative"),
        ("supports_pred_class", 2.9, 8.0, 10.0, False, "contextual"),
        ("supports_pred_class", 2.9, 11.0, 10.0, False, "discriminative"),
        ("supports_pred_class", 9.0, 20.0, 10.0, True, "contextual"),
        ("argues_against_pred_class", 9.0, 20.0, 10.0, False, "contextual"),
    ],
)
def test_evidence_screen_v1_rule(
    direction, z_score, actual, p99, ambiguous, expected
) -> None:
    assert evidence_screen(
        direction=direction,
        z_score_vs_benign=z_score,
        actual_value=actual,
        benign_p99=p99,
        is_ambiguous_pair=ambiguous,
    ) == expected


def test_evidence_mapping_drops_nan_median_and_keeps_empty_case_valid() -> None:
    mapped = map_evidence(
        [
            {
                "representative_feature": "H_weight",
                "actual_value": 12.0,
                "direction": "supports_pred_class",
                "benign_reference": {
                    "median": float("nan"),
                    "std": 1.0,
                    "p99": 10.0,
                    "z_score_vs_benign": 4.0,
                },
            }
        ],
        is_ambiguous_pair=False,
    )
    assert mapped.items == []
    assert mapped.nan_median_dropped == 1


CASES_DIR = Path(__file__).resolve().parents[1] / "evaluation" / "cases"
FROZEN_PATH = CASES_DIR / "eval_cases_frozen.json"
DEV_PATH = CASES_DIR / "eval_cases_dev.json"


@pytest.mark.skipif(
    not (FROZEN_PATH.exists() and DEV_PATH.exists()),
    reason="exported evaluation case files do not exist",
)
def test_exported_case_files_validate_and_round_trip() -> None:
    frozen_cases = load_cases(FROZEN_PATH)
    dev_cases = load_cases(DEV_PATH)
    frozen_records = json.loads(FROZEN_PATH.read_text(encoding="utf-8"))
    dev_records = json.loads(DEV_PATH.read_text(encoding="utf-8"))

    frozen_counts = Counter(record["metadata"]["stratum"] for record in frozen_records)
    assert frozen_counts["assertive_correct"] == 56
    assert 0 <= frozen_counts["assertive_error"] <= 5
    assert frozen_counts["hedged_pair"] == 36
    assert 0 <= frozen_counts["hedged_generic"] <= 6
    pair_truth = Counter(
        record["metadata"]["label_type"]
        for record in frozen_records
        if record["metadata"]["stratum"] == "hedged_pair"
    )
    assert pair_truth == {"gafgyt_tcp": 18, "gafgyt_udp": 18}
    assert len(dev_cases) == 12
    assert Counter(record["metadata"]["stratum"] for record in dev_records) == {
        "assertive_correct": 8,
        "hedged_pair": 4,
    }

    for case, record in zip(frozen_cases + dev_cases, frozen_records + dev_records):
        if record["metadata"]["stratum"] == "hedged_pair":
            assert select_register(case) == "hedged_pair"

    frozen_ids = {record["metadata"]["sample_id"] for record in frozen_records}
    dev_ids = {record["metadata"]["sample_id"] for record in dev_records}
    assert frozen_ids.isdisjoint(dev_ids)
