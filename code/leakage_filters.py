"""Shared feature filters for timestamp-like leakage controls."""

from __future__ import annotations

import re

import numpy as np
import pandas as pd

META_COLS = {"device_name", "label_type", "label_binary", "sample_id"}
TIME_LEAKAGE_EXCLUDED_FAMILIES = frozenset({"HH_jit_mean"})
EPOCH_LIKE_VALUE_THRESHOLD = 1e8


def feature_family(name: str) -> str:
    """Collapse N-BaIoT time-window variants into one feature family."""
    return re.sub(r"_L\d+(\.\d+)?", "", name)


def feature_leakage_audit(
    df: pd.DataFrame,
    candidate_features: list[str] | None = None,
) -> pd.DataFrame:
    """Return per-feature audit rows and the canonical removal decision."""
    features = candidate_features
    if features is None:
        features = [c for c in df.columns if c not in META_COLS]

    rows = []
    for feature in features:
        values = df[feature].to_numpy(dtype=float)
        family = feature_family(feature)
        p75 = float(np.nanquantile(values, 0.75))
        p99 = float(np.nanquantile(values, 0.99))
        max_value = float(np.nanmax(values))
        remove_family = family in TIME_LEAKAGE_EXCLUDED_FAMILIES
        remove_epoch = p75 >= EPOCH_LIKE_VALUE_THRESHOLD
        rows.append({
            "feature": feature,
            "feature_family": family,
            "p75": p75,
            "p99": p99,
            "max": max_value,
            "remove_for_clean_model": bool(remove_family or remove_epoch),
            "remove_reason": (
                "excluded_family"
                if remove_family
                else ("epoch_like_p75" if remove_epoch else "")
            ),
        })
    return pd.DataFrame(rows)


def select_clean_traffic_features(
    df: pd.DataFrame,
    candidate_features: list[str] | None = None,
) -> tuple[list[str], pd.DataFrame]:
    """Select traffic features after removing timestamp-like leakage proxies."""
    audit = feature_leakage_audit(df, candidate_features)
    removed = set(
        audit.loc[audit["remove_for_clean_model"], "feature"].to_numpy()
    )
    features = candidate_features
    if features is None:
        features = [c for c in df.columns if c not in META_COLS]
    return [c for c in features if c not in removed], audit
