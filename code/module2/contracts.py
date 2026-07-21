"""Validated loaders for artifacts exported by the sealed Module 1 pipeline."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pandas as pd
from pandas.api.types import is_numeric_dtype

from .config import CLASS_ORDER, RESULTS_DIR


class ContractValidationError(ValueError):
    """Raised when a Module 1 artifact violates the frozen interface contract."""


ALERT_COLUMNS = (
    "sample_id",
    "device_name",
    "y_pred",
    "p_vector",
    "p_top1",
    "top2_class",
    "p_top2",
    "p_pair",
    "margin",
    "entropy",
    "stage_a_flagged",
    "is_weak_combo",
)

BENIGN_REFERENCE_DEVICES = frozenset(
    {
        "Danmini_Doorbell",
        "Ecobee_Thermostat",
        "Ennio_Doorbell",
        "Philips_B120N10_Baby_Monitor",
        "Provision_PT_737E_Security_Camera",
        "Provision_PT_838_Security_Camera",
        "Samsung_SNH_1011_N_Webcam",
        "SimpleHome_XCS7_1002_WHT_Security_Camera",
        "SimpleHome_XCS7_1003_WHT_Security_Camera",
    }
)

SHAP_PROFILE_COLUMNS = (
    "class",
    "feature_family",
    "mean_abs_shap",
    "mean_signed_shap",
    "representative_feature",
    "representative_feature_mean_abs_shap",
    "n_samples",
)


def _require_schema_list(schema: dict[str, Any], key: str) -> list[str]:
    value = schema.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ContractValidationError(
            f"module1_export_schema.json field {key!r} must be a list of strings"
        )
    return value


def load_export_schema() -> dict[str, Any]:
    """Load and validate the JSON declaration of Module 1 exports."""

    path = RESULTS_DIR / "module1_export_schema.json"
    with path.open(encoding="utf-8") as schema_file:
        schema = json.load(schema_file)

    if not isinstance(schema, dict):
        raise ContractValidationError(
            f"{path.name} must contain a JSON object, got {type(schema).__name__}"
        )

    alert_columns = _require_schema_list(schema, "alerts_full_schema")
    if tuple(alert_columns) != ALERT_COLUMNS:
        raise ContractValidationError(
            "module1_export_schema.json alerts_full_schema does not match the "
            f"frozen Alert contract: expected {list(ALERT_COLUMNS)!r}, "
            f"got {alert_columns!r}"
        )

    class_order = _require_schema_list(schema, "p_vector_class_order")
    if tuple(class_order) != CLASS_ORDER:
        raise ContractValidationError(
            "module1_export_schema.json p_vector_class_order does not match the "
            f"frozen class order: expected {list(CLASS_ORDER)!r}, got {class_order!r}"
        )

    return schema


def load_alerts() -> pd.DataFrame:
    """Load alerts and reject column or probability-vector schema drift."""

    schema = load_export_schema()
    expected_columns = _require_schema_list(schema, "alerts_full_schema")
    path = RESULTS_DIR / "alerts_full.parquet"
    alerts = pd.read_parquet(path)

    actual_columns = list(alerts.columns)
    if len(actual_columns) != len(expected_columns) or set(actual_columns) != set(
        expected_columns
    ):
        missing = sorted(set(expected_columns) - set(actual_columns))
        unexpected = sorted(set(actual_columns) - set(expected_columns))
        raise ContractValidationError(
            f"{path.name} column mismatch: missing={missing!r}, "
            f"unexpected={unexpected!r}; expected exactly {expected_columns!r}"
        )

    def has_expected_vector_length(value: Any) -> bool:
        if isinstance(value, (str, bytes)):
            return False
        try:
            return len(value) == len(CLASS_ORDER)
        except TypeError:
            return False

    valid_vectors = alerts["p_vector"].map(has_expected_vector_length)
    if not bool(valid_vectors.all()):
        bad_rows = alerts.index[~valid_vectors].tolist()[:5]
        raise ContractValidationError(
            f"{path.name} contains p_vector values whose length is not "
            f"{len(CLASS_ORDER)}; first invalid row indices: {bad_rows!r}"
        )

    return alerts


def load_benign_reference_stats() -> pd.DataFrame:
    """Load per-device benign statistics and validate their tabular shape."""

    path = RESULTS_DIR / "benign_reference_stats.parquet"
    stats = pd.read_parquet(path)
    if stats.empty:
        raise ContractValidationError(f"{path.name} must not be empty")
    if stats.index.name != "device_name" or stats.index.has_duplicates:
        raise ContractValidationError(
            f"{path.name} must have a unique index named 'device_name'"
        )

    actual_devices = frozenset(stats.index)
    if actual_devices != BENIGN_REFERENCE_DEVICES:
        missing = sorted(BENIGN_REFERENCE_DEVICES - actual_devices)
        unexpected = sorted(actual_devices - BENIGN_REFERENCE_DEVICES)
        raise ContractValidationError(
            f"{path.name} device coverage mismatch: missing={missing!r}, "
            f"unexpected={unexpected!r}"
        )

    if not isinstance(stats.columns, pd.MultiIndex) or stats.columns.nlevels != 2:
        raise ContractValidationError(
            f"{path.name} columns must be a two-level (feature, statistic) MultiIndex"
        )
    if stats.columns.has_duplicates:
        raise ContractValidationError(f"{path.name} contains duplicate columns")

    expected_statistics = {"median", "std", "p99"}
    feature_statistics: dict[Any, set[Any]] = {}
    for feature, statistic in stats.columns:
        feature_statistics.setdefault(feature, set()).add(statistic)
    incomplete_features = sorted(
        str(feature)
        for feature, statistics in feature_statistics.items()
        if statistics != expected_statistics
    )
    if incomplete_features:
        raise ContractValidationError(
            f"{path.name} features must each provide median, std, and p99; "
            f"invalid features: {incomplete_features[:5]!r}"
        )
    if not all(is_numeric_dtype(dtype) for dtype in stats.dtypes):
        raise ContractValidationError(f"{path.name} statistic columns must be numeric")

    return stats


def load_shap_global_profiles() -> pd.DataFrame:
    """Load class-level SHAP profiles and validate their basic shape."""

    path = RESULTS_DIR / "shap_global_profiles.parquet"
    profiles = pd.read_parquet(path)
    if profiles.empty:
        raise ContractValidationError(f"{path.name} must not be empty")

    actual_columns = list(profiles.columns)
    if tuple(actual_columns) != SHAP_PROFILE_COLUMNS:
        raise ContractValidationError(
            f"{path.name} columns must be {list(SHAP_PROFILE_COLUMNS)!r}, "
            f"got {actual_columns!r}"
        )
    actual_classes = set(profiles["class"])
    if actual_classes != set(CLASS_ORDER):
        missing = sorted(set(CLASS_ORDER) - actual_classes)
        unexpected = sorted(actual_classes - set(CLASS_ORDER))
        raise ContractValidationError(
            f"{path.name} class coverage mismatch: missing={missing!r}, "
            f"unexpected={unexpected!r}"
        )
    if profiles.duplicated(["class", "feature_family"]).any():
        raise ContractValidationError(
            f"{path.name} contains duplicate class/feature_family rows"
        )
    if profiles.isna().any(axis=None):
        raise ContractValidationError(f"{path.name} must not contain null values")

    return profiles


@dataclass(frozen=True, slots=True)
class Alert:
    """Typed representation of one row from ``alerts_full.parquet``."""

    sample_id: int
    device_name: str
    y_pred: str
    p_vector: tuple[float, ...]
    p_top1: float
    top2_class: str
    p_top2: float
    p_pair: float
    margin: float
    entropy: float
    stage_a_flagged: bool
    is_weak_combo: bool

    def __post_init__(self) -> None:
        if len(self.p_vector) != len(CLASS_ORDER):
            raise ContractValidationError(
                f"Alert.p_vector must have length {len(CLASS_ORDER)}, "
                f"got {len(self.p_vector)}"
            )

    @classmethod
    def from_row(cls, row: pd.Series | Mapping[str, Any]) -> Alert:
        """Construct an ``Alert`` from a pandas row or mapping."""

        keys = set(row.index if isinstance(row, pd.Series) else row.keys())
        missing = sorted(set(ALERT_COLUMNS) - keys)
        if missing:
            raise ContractValidationError(
                f"Cannot construct Alert; row is missing fields: {missing!r}"
            )

        return cls(
            sample_id=int(row["sample_id"]),
            device_name=str(row["device_name"]),
            y_pred=str(row["y_pred"]),
            p_vector=tuple(float(value) for value in row["p_vector"]),
            p_top1=float(row["p_top1"]),
            top2_class=str(row["top2_class"]),
            p_top2=float(row["p_top2"]),
            p_pair=float(row["p_pair"]),
            margin=float(row["margin"]),
            entropy=float(row["entropy"]),
            stage_a_flagged=bool(row["stage_a_flagged"]),
            is_weak_combo=bool(row["is_weak_combo"]),
        )
