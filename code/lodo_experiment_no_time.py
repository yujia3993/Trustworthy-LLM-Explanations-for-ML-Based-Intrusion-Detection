"""
Leave-One-Device-Out (LODO) validation after removing timestamp-like features.

This is the leakage-controlled companion to lodo_experiment.py. It keeps the
same LODO protocol and XGBoost settings, but removes:
  - HH_jit_mean feature family
  - any traffic feature whose 75th percentile is epoch-scale

Outputs are written to ../results_lodo_no_time/ so the original LODO artifacts
remain untouched.
"""

from __future__ import annotations

import json
import logging
import re
import sys
import time
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix, f1_score, recall_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from train_stage_b import RANDOM_STATE, XGB_PARAMS

logger = logging.getLogger(__name__)

META_COLS = {"device_name", "label_type", "label_binary", "sample_id"}
EXCLUDED_FAMILIES = frozenset({"HH_jit_mean"})
EPOCH_LIKE_VALUE_THRESHOLD = 1e8
TCP_CLASS = "gafgyt_tcp"
UDP_CLASS = "gafgyt_udp"


def feature_family(name: str) -> str:
    """Collapse N-BaIoT time-window variants into one feature family."""
    return re.sub(r"_L\d+(\.\d+)?", "", name)


def feature_removal_audit(df: pd.DataFrame) -> pd.DataFrame:
    """Identify timestamp-like traffic features removed for this LODO run."""
    rows = []
    traffic_cols = [c for c in df.columns if c not in META_COLS]
    for feature in traffic_cols:
        values = df[feature].to_numpy(dtype=float)
        family = feature_family(feature)
        p75 = float(np.nanquantile(values, 0.75))
        p99 = float(np.nanquantile(values, 0.99))
        max_value = float(np.nanmax(values))
        remove_family = family in EXCLUDED_FAMILIES
        remove_epoch = p75 >= EPOCH_LIKE_VALUE_THRESHOLD
        rows.append({
            "feature": feature,
            "feature_family": family,
            "p75": p75,
            "p99": p99,
            "max": max_value,
            "remove_for_lodo_no_time": bool(remove_family or remove_epoch),
            "remove_reason": (
                "excluded_family"
                if remove_family
                else ("epoch_like_p75" if remove_epoch else "")
            ),
        })
    return pd.DataFrame(rows)


def get_no_time_features(df: pd.DataFrame, audit: pd.DataFrame) -> list[str]:
    removed = set(
        audit.loc[audit["remove_for_lodo_no_time"], "feature"].to_numpy()
    )
    return [c for c in df.columns if c not in META_COLS and c not in removed]


def tcp_udp_counts(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    class_names: np.ndarray,
) -> dict[str, int | float]:
    tcp_idx = int(np.where(class_names == TCP_CLASS)[0][0])
    udp_idx = int(np.where(class_names == UDP_CLASS)[0][0])
    tcp_mask = y_true == tcp_idx
    udp_mask = y_true == udp_idx
    return {
        "tcp_support": int(tcp_mask.sum()),
        "udp_support": int(udp_mask.sum()),
        "tcp_to_udp": int(((tcp_mask) & (y_pred == udp_idx)).sum()),
        "udp_to_tcp": int(((udp_mask) & (y_pred == tcp_idx)).sum()),
        "tcp_recall": float((y_pred[tcp_mask] == tcp_idx).mean()) if tcp_mask.any() else np.nan,
        "udp_recall": float((y_pred[udp_mask] == udp_idx).mean()) if udp_mask.any() else np.nan,
    }


def run_lodo_no_time(df: pd.DataFrame, out_dir: Path) -> pd.DataFrame:
    out_dir.mkdir(parents=True, exist_ok=True)

    audit = feature_removal_audit(df)
    audit.to_csv(out_dir / "removed_features.csv", index=False)
    feature_cols = get_no_time_features(df, audit)
    joblib.dump(feature_cols, out_dir / "lodo_no_time_feature_cols.joblib")

    removed_count = int(audit["remove_for_lodo_no_time"].sum())
    logger.info(
        "Using %d no-time traffic features (%d removed, no device one-hot)",
        len(feature_cols),
        removed_count,
    )

    le = LabelEncoder()
    df = df.copy()
    df["y"] = le.fit_transform(df["label_type"].values)
    benign_idx = list(le.classes_).index("benign")
    devices = sorted(df["device_name"].unique())

    fold_path = out_dir / "lodo_results.csv"
    per_class_path = out_dir / "lodo_per_class_f1.csv"
    if fold_path.exists():
        fold_rows = pd.read_csv(fold_path).to_dict(orient="records")
        completed_devices = {row["held_out_device"] for row in fold_rows}
        logger.info("Resuming from %s (%d completed folds)", fold_path, len(fold_rows))
    else:
        fold_rows = []
        completed_devices = set()

    if per_class_path.exists():
        per_class_rows = pd.read_csv(per_class_path).to_dict(orient="records")
    else:
        per_class_rows = []

    confusion_dir = out_dir / "confusion_matrices"
    confusion_dir.mkdir(parents=True, exist_ok=True)

    for i, device in enumerate(devices, 1):
        if device in completed_devices:
            logger.info("[%d/%d] Skipping completed fold %s", i, len(devices), device)
            continue

        t0 = time.time()
        train_df = df[df["device_name"] != device]
        test_df = df[df["device_name"] == device]

        X_train = train_df[feature_cols].values
        y_train = train_df["y"].values
        X_test = test_df[feature_cols].values
        y_test = test_df["y"].values
        test_classes = np.unique(y_test)

        logger.info(
            "[%d/%d] Holding out %s: train=%d, test=%d, test classes=%d",
            i,
            len(devices),
            device,
            len(y_train),
            len(y_test),
            len(test_classes),
        )

        model = XGBClassifier(**XGB_PARAMS, num_class=len(le.classes_))
        model.fit(X_train, y_train)
        preds = model.predict_proba(X_test).argmax(axis=1)

        macro_f1 = f1_score(
            y_test, preds, labels=test_classes, average="macro", zero_division=0
        )
        weighted_f1 = f1_score(
            y_test, preds, labels=test_classes, average="weighted", zero_division=0
        )
        accuracy = float((preds == y_test).mean())

        y_bin = (y_test != benign_idx).astype(int)
        p_bin = (preds != benign_idx).astype(int)
        attack_recall = recall_score(y_bin, p_bin, zero_division=0)
        benign_mask = y_bin == 0
        benign_fpr = float(p_bin[benign_mask].mean()) if benign_mask.any() else np.nan

        elapsed = time.time() - t0
        tcp_udp = tcp_udp_counts(y_test, preds, le.classes_)
        fold_rows.append({
            "held_out_device": device,
            "n_train": len(y_train),
            "n_test": len(y_test),
            "n_test_classes": len(test_classes),
            "macro_f1": macro_f1,
            "weighted_f1": weighted_f1,
            "accuracy": accuracy,
            "binary_attack_recall": attack_recall,
            "binary_benign_fpr": benign_fpr,
            "tcp_support": tcp_udp["tcp_support"],
            "udp_support": tcp_udp["udp_support"],
            "tcp_to_udp": tcp_udp["tcp_to_udp"],
            "udp_to_tcp": tcp_udp["udp_to_tcp"],
            "tcp_recall": tcp_udp["tcp_recall"],
            "udp_recall": tcp_udp["udp_recall"],
            "fit_seconds": round(elapsed, 1),
        })
        logger.info(
            "    macro-F1=%.4f weighted-F1=%.4f bin-recall=%.4f "
            "tcp->udp=%d udp->tcp=%d (%.0fs)",
            macro_f1,
            weighted_f1,
            attack_recall,
            tcp_udp["tcp_to_udp"],
            tcp_udp["udp_to_tcp"],
            elapsed,
        )

        report = classification_report(
            y_test,
            preds,
            labels=test_classes,
            target_names=[le.classes_[c] for c in test_classes],
            output_dict=True,
            zero_division=0,
        )
        for cls_name in (le.classes_[c] for c in test_classes):
            per_class_rows.append({
                "held_out_device": device,
                "class": cls_name,
                "f1": report[cls_name]["f1-score"],
                "precision": report[cls_name]["precision"],
                "recall": report[cls_name]["recall"],
                "support": int(report[cls_name]["support"]),
            })

        cm = confusion_matrix(y_test, preds, labels=np.arange(len(le.classes_)))
        cm_df = pd.DataFrame(
            cm, index=le.classes_, columns=le.classes_
        )
        safe_device = re.sub(r"[^A-Za-z0-9_.-]+", "_", device).strip("_")
        cm_df.to_csv(confusion_dir / f"{safe_device}.csv")

        pd.DataFrame(fold_rows).to_csv(fold_path, index=False)
        pd.DataFrame(per_class_rows).to_csv(per_class_path, index=False)
        logger.info("    checkpoint saved after %s", device)

    fold_df = pd.DataFrame(fold_rows)
    per_class_df = pd.DataFrame(per_class_rows)
    fold_df.to_csv(fold_path, index=False)
    per_class_df.to_csv(per_class_path, index=False)

    summary = {
        "scope": "lodo_no_time_features",
        "feature_filter": {
            "removed_feature_count": removed_count,
            "kept_feature_count": len(feature_cols),
            "removed_families": sorted(
                audit.loc[
                    audit["remove_for_lodo_no_time"], "feature_family"
                ].unique()
            ),
            "epoch_like_rule": f"p75 >= {EPOCH_LIKE_VALUE_THRESHOLD}",
            "family_rule": sorted(EXCLUDED_FAMILIES),
        },
        "macro_f1": {
            "mean": float(fold_df["macro_f1"].mean()),
            "median": float(fold_df["macro_f1"].median()),
            "min": float(fold_df["macro_f1"].min()),
            "max": float(fold_df["macro_f1"].max()),
        },
        "binary_attack_recall_mean": float(fold_df["binary_attack_recall"].mean()),
        "tcp_udp_total": {
            "tcp_to_udp": int(fold_df["tcp_to_udp"].sum()),
            "udp_to_tcp": int(fold_df["udp_to_tcp"].sum()),
            "tcp_support": int(fold_df["tcp_support"].sum()),
            "udp_support": int(fold_df["udp_support"].sum()),
        },
        "worst_folds": fold_df.nsmallest(3, "macro_f1")[
            ["held_out_device", "macro_f1"]
        ].to_dict(orient="records"),
    }
    (out_dir / "lodo_no_time_summary.json").write_text(
        json.dumps(summary, indent=2),
        encoding="utf-8",
    )

    return fold_df


def print_summary(fold_df: pd.DataFrame) -> None:
    print("\n=== LODO no-time fold results ===")
    print(fold_df.drop(columns=["fit_seconds"]).to_string(index=False))

    mf1 = fold_df["macro_f1"]
    print("\n=== LODO no-time summary ===")
    print(f"  macro-F1 range : [{mf1.min():.3f}, {mf1.max():.3f}]")
    print(f"  macro-F1 mean  : {mf1.mean():.3f}  (median {mf1.median():.3f})")
    print(
        f"  binary attack recall mean: "
        f"{fold_df['binary_attack_recall'].mean():.3f}"
    )
    print(
        "  tcp/udp swaps: "
        f"tcp->udp={int(fold_df['tcp_to_udp'].sum())}, "
        f"udp->tcp={int(fold_df['udp_to_tcp'].sum())}"
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    script_dir = Path(__file__).resolve().parent
    default_data_path = script_dir / "nbaiot_sampled.parquet"
    data_path = Path(sys.argv[1]) if len(sys.argv) > 1 else default_data_path
    if not data_path.exists():
        sys.exit(f"Data file not found: {data_path}")

    df = pd.read_parquet(data_path)
    logger.info("Loaded %d rows from %s", len(df), data_path)

    out_dir = script_dir.parent / "results_lodo_no_time"
    fold_df = run_lodo_no_time(df, out_dir=out_dir)
    print_summary(fold_df)
