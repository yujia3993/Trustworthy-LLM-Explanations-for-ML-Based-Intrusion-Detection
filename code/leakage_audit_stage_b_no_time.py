"""
One-shot Stage B leakage audit.

This script retrains Stage B once after removing timestamp-like traffic
features from the feature matrix. It is deliberately scoped to the existing
row-level Stage B split; it does not run LODO.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from module1_exports import (
    EPOCH_LIKE_VALUE_THRESHOLD,
    EXPLANATION_EXCLUDE_FAMILIES,
    feature_family,
    load_artifacts,
    prepare_stage_b_features,
)
from train_stage_b import CALIB_FRACTION, RANDOM_STATE, TEST_FRACTION, XGB_PARAMS
from train_stage_b import run_stage_a_on_test

logger = logging.getLogger(__name__)


def select_removed_features(df: pd.DataFrame) -> pd.DataFrame:
    meta_cols = {"device_name", "label_type", "label_binary", "sample_id"}
    traffic_cols = [c for c in df.columns if c not in meta_cols]
    rows = []
    for feature in traffic_cols:
        values = df[feature].to_numpy(dtype=float)
        family = feature_family(feature)
        p75 = float(np.nanquantile(values, 0.75))
        p99 = float(np.nanquantile(values, 0.99))
        max_value = float(np.nanmax(values))
        remove_family = family in EXPLANATION_EXCLUDE_FAMILIES
        remove_epoch = p75 >= EPOCH_LIKE_VALUE_THRESHOLD
        rows.append({
            "feature": feature,
            "feature_family": family,
            "p75": p75,
            "p99": p99,
            "max": max_value,
            "remove_for_audit": bool(remove_family or remove_epoch),
            "remove_reason": "excluded_family"
            if remove_family else ("epoch_like_p75" if remove_epoch else ""),
        })
    return pd.DataFrame(rows)


def prepare_no_time_features(
    df: pd.DataFrame,
    removed: pd.DataFrame,
) -> tuple[pd.DataFrame, list[str]]:
    removed_features = set(
        removed.loc[removed["remove_for_audit"], "feature"].to_numpy()
    )
    meta_cols = {"device_name", "label_type", "label_binary", "sample_id"}
    traffic_cols = [
        c for c in df.columns
        if c not in meta_cols and c not in removed_features
    ]
    device_dummies = pd.get_dummies(df["device_name"], prefix="dev")
    X = pd.concat([df[traffic_cols], device_dummies], axis=1)
    return X, list(X.columns)


def split_indices(y: np.ndarray) -> dict[str, np.ndarray]:
    indices = np.arange(len(y))
    trainval_idx, test_idx, y_trainval, _ = train_test_split(
        indices,
        y,
        test_size=TEST_FRACTION,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    train_idx, calib_idx, _, _ = train_test_split(
        trainval_idx,
        y_trainval,
        test_size=CALIB_FRACTION,
        stratify=y_trainval,
        random_state=RANDOM_STATE,
    )
    return {"train": train_idx, "calib": calib_idx, "test": test_idx}


def tcp_udp_counts(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: np.ndarray,
    stage_a_flags: np.ndarray | None = None,
) -> dict[str, int]:
    tcp_idx = int(np.where(class_names == "gafgyt_tcp")[0][0])
    udp_idx = int(np.where(class_names == "gafgyt_udp")[0][0])
    mask = np.ones(len(y_true), dtype=bool)
    if stage_a_flags is not None:
        mask &= stage_a_flags
    return {
        "tcp_support": int(((y_true == tcp_idx) & mask).sum()),
        "udp_support": int(((y_true == udp_idx) & mask).sum()),
        "tcp_to_udp": int(((y_true == tcp_idx) & (y_pred == udp_idx) & mask).sum()),
        "udp_to_tcp": int(((y_true == udp_idx) & (y_pred == tcp_idx) & mask).sum()),
    }


def metrics_block(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: np.ndarray,
    stage_a_flags: np.ndarray,
) -> dict[str, object]:
    cm = confusion_matrix(y_true, y_pred, labels=np.arange(len(class_names)))
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "macro_f1": float(f1_score(
            y_true, y_pred, labels=np.arange(len(class_names)),
            average="macro", zero_division=0,
        )),
        "weighted_f1": float(f1_score(
            y_true, y_pred, labels=np.arange(len(class_names)),
            average="weighted", zero_division=0,
        )),
        "tcp_udp_standalone": tcp_udp_counts(y_true, y_pred, class_names),
        "tcp_udp_gated": tcp_udp_counts(
            y_true, y_pred, class_names, stage_a_flags=stage_a_flags
        ),
        "confusion_matrix": cm.tolist(),
    }


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )
    script_dir = Path(__file__).resolve().parent
    data_path = script_dir / "nbaiot_sampled.parquet"
    models_dir = script_dir / "models"
    results_dir = script_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Loading %s", data_path)
    df = pd.read_parquet(data_path)
    if "sample_id" not in df.columns:
        df = df.copy()
        df["sample_id"] = df.index

    label_encoder = LabelEncoder()
    y = label_encoder.fit_transform(df["label_type"].to_numpy())
    splits = split_indices(y)

    removed = select_removed_features(df)
    removed_path = results_dir / "leakage_audit_removed_features.csv"
    removed.to_csv(removed_path, index=False)

    X_no_time, feature_cols = prepare_no_time_features(df, removed)
    X_train = X_no_time.iloc[splits["train"]]
    y_train = y[splits["train"]]
    X_test = X_no_time.iloc[splits["test"]]
    y_test = y[splits["test"]]

    logger.info(
        "Training no-time Stage B with %d features (%d removed)",
        len(feature_cols),
        int(removed["remove_for_audit"].sum()),
    )
    model = XGBClassifier(**XGB_PARAMS, num_class=len(label_encoder.classes_))
    model.fit(X_train, y_train)
    no_time_preds = model.predict_proba(X_test).argmax(axis=1)

    test_df = df.iloc[splits["test"]].reset_index(drop=True)
    stage_a_flags = run_stage_a_on_test(test_df, models_dir)
    no_time = metrics_block(
        y_test, no_time_preds, label_encoder.classes_, stage_a_flags
    )

    artifacts = load_artifacts(models_dir)
    X_baseline = prepare_stage_b_features(df, artifacts["feature_cols"])
    baseline_probs = artifacts["calibrated"].predict_proba(
        X_baseline.iloc[splits["test"]].reset_index(drop=True)
    )
    baseline_preds = baseline_probs.argmax(axis=1)
    baseline = metrics_block(
        y_test, baseline_preds, artifacts["label_encoder"].classes_, stage_a_flags
    )

    summary = {
        "scope": "row_level_stage_b_split_only_not_lodo",
        "split": {
            "test_fraction": TEST_FRACTION,
            "calib_fraction": CALIB_FRACTION,
            "random_state": RANDOM_STATE,
            "n_train": int(len(splits["train"])),
            "n_calib": int(len(splits["calib"])),
            "n_test": int(len(splits["test"])),
        },
        "feature_filter": {
            "removed_feature_count": int(removed["remove_for_audit"].sum()),
            "kept_feature_count": int(len(feature_cols)),
            "removed_families": sorted(
                removed.loc[
                    removed["remove_for_audit"], "feature_family"
                ].unique()
            ),
            "epoch_like_rule": f"p75 >= {EPOCH_LIKE_VALUE_THRESHOLD}",
            "family_rule": sorted(EXPLANATION_EXCLUDE_FAMILIES),
        },
        "baseline_saved_model": baseline,
        "no_time_retrained_once": no_time,
        "delta_no_time_minus_baseline": {
            "macro_f1": no_time["macro_f1"] - baseline["macro_f1"],
            "accuracy": no_time["accuracy"] - baseline["accuracy"],
            "tcp_to_udp_standalone": (
                no_time["tcp_udp_standalone"]["tcp_to_udp"]
                - baseline["tcp_udp_standalone"]["tcp_to_udp"]
            ),
            "tcp_to_udp_gated": (
                no_time["tcp_udp_gated"]["tcp_to_udp"]
                - baseline["tcp_udp_gated"]["tcp_to_udp"]
            ),
        },
    }

    summary_path = results_dir / "leakage_audit_stage_b_no_time.json"
    summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    joblib.dump(feature_cols, results_dir / "leakage_audit_no_time_feature_cols.joblib")
    logger.info("Saved leakage audit summary -> %s", summary_path)


if __name__ == "__main__":
    main()
