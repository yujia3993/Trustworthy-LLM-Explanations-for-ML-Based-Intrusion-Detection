"""
lodo_experiment.py — Leave-One-Device-Out (LODO) validation for Stage B.

Purpose
-------
The standard row-level random split yields macro-F1 ≈ 0.998, which is
optimistic because rows within the same capture file are highly
autocorrelated. This script answers a different question:

    "How well do attack signatures learned on 8 devices generalise
     to a 9th device the model has never seen?"

For each of the 9 devices: train XGBoost on the other 8, test on the
held-out one. One-shot experiment: results are written to ./results/
and summarised to stdout. Not part of the production pipeline.

Design decisions (documented for the README / write-up)
--------------------------------------------------------
1. TRAFFIC FEATURES ONLY (115 cols), no device one-hot.
   The production Stage B uses 9 device dummy columns, but in LODO the
   held-out device's dummy never appears in training, so including it
   would either leak identity (if set) or be out-of-distribution noise
   (if zeroed). Dropping the dummies asks the clean question: do the
   *traffic* signatures generalise?
2. NO ISOTONIC CALIBRATION.
   Calibration rescales probabilities; for argmax classification and
   F1 it is near-neutral. Skipping it keeps each fold to a single fit.
3. MACRO-F1 OVER CLASSES PRESENT ON THE TEST DEVICE.
   Two devices (Ennio_Doorbell, Samsung_SNH_1011_N_Webcam) have Gafgyt
   only — averaging over absent Mirai classes would artificially drag
   their scores to ~0.5 for the wrong reason.
4. SHARED LABEL ENCODER fit on the full dataset, so class indices are
   consistent across folds and with the production model.

Expected runtime: ~10–30 min on a laptop (9 × XGBoost, hist method).

Usage
-----
    python lodo_experiment.py [path/to/nbaiot_sampled.parquet]
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score, recall_score
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

logger = logging.getLogger(__name__)

RANDOM_STATE = 42

# Same hyperparameters as production train_stage_b.py — the point of the
# experiment is to change the SPLIT, not the model.
XGB_PARAMS = dict(
    n_estimators=400,
    max_depth=6,
    learning_rate=0.1,
    objective="multi:softprob",
    eval_metric="mlogloss",
    n_jobs=-1,
    random_state=RANDOM_STATE,
    tree_method="hist",
)

META_COLS = {"device_name", "label_type", "label_binary"}


def get_traffic_features(df: pd.DataFrame) -> list[str]:
    """The 115 traffic feature columns (everything except metadata)."""
    return [c for c in df.columns if c not in META_COLS]


def run_lodo(df: pd.DataFrame, out_dir: Path) -> pd.DataFrame:
    results_dir = out_dir / "results"
    results_dir.mkdir(parents=True, exist_ok=True)

    feature_cols = get_traffic_features(df)
    logger.info(f"Using {len(feature_cols)} traffic features (no device one-hot)")

    # Shared encoder: consistent class indices across all folds
    le = LabelEncoder()
    df = df.copy()
    df["y"] = le.fit_transform(df["label_type"].values)
    benign_idx = list(le.classes_).index("benign")
    logger.info(f"Classes ({len(le.classes_)}): {list(le.classes_)}")

    devices = sorted(df["device_name"].unique())
    logger.info(f"Devices ({len(devices)}): {devices}")

    fold_rows = []
    per_class_rows = []

    for i, device in enumerate(devices, 1):
        t0 = time.time()
        train_df = df[df["device_name"] != device]
        test_df = df[df["device_name"] == device]

        X_train = train_df[feature_cols].values
        y_train = train_df["y"].values
        X_test = test_df[feature_cols].values
        y_test = test_df["y"].values

        test_classes = np.unique(y_test)
        logger.info(
            f"[{i}/{len(devices)}] Holding out {device}: "
            f"train={len(y_train):,}, test={len(y_test):,}, "
            f"test classes={len(test_classes)}"
        )

        model = XGBClassifier(**XGB_PARAMS, num_class=len(le.classes_))
        model.fit(X_train, y_train)
        preds = model.predict_proba(X_test).argmax(axis=1)

        # --- Multiclass metrics over classes present on this device ---
        macro_f1 = f1_score(
            y_test, preds, labels=test_classes, average="macro", zero_division=0
        )
        weighted_f1 = f1_score(
            y_test, preds, labels=test_classes, average="weighted", zero_division=0
        )
        accuracy = (preds == y_test).mean()

        # --- Binary view: would an attack at least be flagged as SOME attack? ---
        y_bin = (y_test != benign_idx).astype(int)
        p_bin = (preds != benign_idx).astype(int)
        attack_recall = recall_score(y_bin, p_bin, zero_division=0)
        benign_mask = y_bin == 0
        benign_fpr = p_bin[benign_mask].mean() if benign_mask.any() else np.nan

        elapsed = time.time() - t0
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
            "fit_seconds": round(elapsed, 1),
        })
        logger.info(
            f"    macro-F1={macro_f1:.4f}  weighted-F1={weighted_f1:.4f}  "
            f"bin-recall={attack_recall:.4f}  bin-FPR={benign_fpr:.4f}  "
            f"({elapsed:.0f}s)"
        )

        # --- Per-class F1, long format (feeds RQ2: which device/attack
        #     combinations deserve more conservative report language) ---
        report = classification_report(
            y_test, preds,
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

    fold_df = pd.DataFrame(fold_rows)
    per_class_df = pd.DataFrame(per_class_rows)

    fold_path = results_dir / "lodo_results.csv"
    per_class_path = results_dir / "lodo_per_class_f1.csv"
    fold_df.to_csv(fold_path, index=False)
    per_class_df.to_csv(per_class_path, index=False)
    logger.info(f"Saved fold summary  -> {fold_path}")
    logger.info(f"Saved per-class F1  -> {per_class_path}")

    return fold_df


def print_summary(fold_df: pd.DataFrame) -> None:
    print("\n=== LODO fold results ===")
    print(fold_df.drop(columns=["fit_seconds"]).to_string(index=False))

    mf1 = fold_df["macro_f1"]
    print("\n=== LODO summary (paste into README headline table) ===")
    print(f"  macro-F1 range : [{mf1.min():.3f}, {mf1.max():.3f}]")
    print(f"  macro-F1 mean  : {mf1.mean():.3f}  (median {mf1.median():.3f})")
    print(f"  vs row-level random split: 0.998")
    print(
        f"  binary attack recall mean: "
        f"{fold_df['binary_attack_recall'].mean():.3f}"
    )

    worst = fold_df.nsmallest(3, "macro_f1")[["held_out_device", "macro_f1"]]
    print("\n  Weakest generalisation (candidates for conservative "
          "report language in RQ2):")
    for _, r in worst.iterrows():
        print(f"    {r['held_out_device']}: {r['macro_f1']:.3f}")


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
    logger.info(f"Loaded {len(df):,} rows from {data_path}")

    fold_df = run_lodo(df, out_dir=Path("."))
    print_summary(fold_df)
