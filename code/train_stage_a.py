"""
Stage A: Per-device Isolation Forest training and evaluation.

For each of the 9 IoT devices:
  1. Train Isolation Forest on benign_traffic only, using L1 (1.5s window) features.
  2. Evaluate on held-out benign + all attack samples for that device.
  3. Report attack recall, benign FPR, per-attack-type recall.

Outputs:
  - models/if_<device_name>.joblib       : trained models
  - models/scaler_<device_name>.joblib   : per-device feature scalers
  - results/stage_a_summary.csv          : per-device metrics
  - results/stage_a_per_attack.csv       : per-(device, attack_type) recall
"""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

from leakage_filters import select_clean_traffic_features

logger = logging.getLogger(__name__)

# Reproducibility
RANDOM_STATE = 42

# IF hyperparameters - tuned for IoT traffic at the L1 (1.5s) window
IF_PARAMS = dict(
    n_estimators=200,
    max_samples=256,          # IF default; balances tree depth and speed
    contamination="auto",     # use the offset_ heuristic, NOT a hand-picked rate
    random_state=RANDOM_STATE,
    n_jobs=-1,
)

# Train/test split for benign data
BENIGN_TEST_FRACTION = 0.3


def select_if_features(df: pd.DataFrame) -> list[str]:
    """
    Return feature columns for IF training across three time windows:
      - L1   (1.5s)  : catches fast/burst attacks like Mirai floods
      - L0.1 (10s)   : catches medium-rate sustained activity
      - L0.01 (1min) : catches slow-burn low-rate floods like Gafgyt tcp/udp

    We deliberately drop L5 (100ms) and L3 (500ms) - these are jitter-dominated
    and add noise without separable signal.
    """
    # Note: N-BaIoT uses '_L0.1_' and '_L0.01_' literally in column names
    keep_tokens = ("_L1_", "_L0.1_", "_L0.01_")
    candidate_features = [c for c in df.columns if any(tok in c for tok in keep_tokens)]
    clean_features, _ = select_clean_traffic_features(df, candidate_features)
    return clean_features


# Back-compat alias - some downstream code may still call the old name
select_l1_features = select_if_features


def train_one_device(
    device_df: pd.DataFrame,
    feature_cols: list[str],
) -> tuple[IsolationForest, StandardScaler, dict]:
    """
    Train IF for a single device.

    Returns:
        model, scaler, metrics_dict
    """
    device_name = device_df["device_name"].iloc[0]
    benign = device_df[device_df["label_binary"] == 0]
    attacks = device_df[device_df["label_binary"] == 1]

    if len(benign) < 100:
        raise ValueError(
            f"{device_name}: only {len(benign)} benign rows, too few to train IF"
        )

    # Split benign into train (baseline) and test (FPR evaluation)
    benign_train, benign_test = train_test_split(
        benign,
        test_size=BENIGN_TEST_FRACTION,
        random_state=RANDOM_STATE,
    )

    X_train = benign_train[feature_cols].values
    X_benign_test = benign_test[feature_cols].values
    X_attack_test = attacks[feature_cols].values

    # Per-device scaling: IF is not strictly scale-sensitive but standardisation
    # stabilises tree splits when features span very different magnitudes.
    scaler = StandardScaler()
    X_train_s = scaler.fit_transform(X_train)
    X_benign_test_s = scaler.transform(X_benign_test)
    X_attack_test_s = scaler.transform(X_attack_test)

    # Fit
    model = IsolationForest(**IF_PARAMS)
    model.fit(X_train_s)

    # Predict: IF returns +1 for inlier (benign), -1 for outlier (attack)
    benign_preds = model.predict(X_benign_test_s)
    attack_preds = model.predict(X_attack_test_s)

    # Convert to "flagged as anomaly" boolean
    benign_flagged = (benign_preds == -1)
    attack_flagged = (attack_preds == -1)

    fpr = benign_flagged.mean()                  # we want this low
    attack_recall = attack_flagged.mean()        # we want this high

    # Anomaly scores for downstream threshold tuning
    # decision_function: higher = more normal, lower = more anomalous
    benign_scores = model.decision_function(X_benign_test_s)
    attack_scores = model.decision_function(X_attack_test_s)

    metrics = {
        "device_name": device_name,
        "n_benign_train": len(benign_train),
        "n_benign_test": len(benign_test),
        "n_attack_test": len(attacks),
        "benign_fpr": fpr,
        "attack_recall": attack_recall,
        "benign_score_mean": benign_scores.mean(),
        "benign_score_std": benign_scores.std(),
        "attack_score_mean": attack_scores.mean(),
        "attack_score_std": attack_scores.std(),
    }

    # Per-attack-type breakdown (Mirai vs Gafgyt and variants)
    per_attack_rows = []
    for atk_type, grp in attacks.groupby("label_type"):
        X_at = scaler.transform(grp[feature_cols].values)
        preds_at = model.predict(X_at)
        recall_at = (preds_at == -1).mean()
        per_attack_rows.append({
            "device_name": device_name,
            "attack_type": atk_type,
            "n_samples": len(grp),
            "recall": recall_at,
        })

    metrics["per_attack"] = pd.DataFrame(per_attack_rows)
    return model, scaler, metrics


def train_all_devices(
    df: pd.DataFrame,
    out_dir: Path,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """Train one IF per device, save artefacts, return summary + per-attack tables."""
    models_dir = out_dir / "models"
    results_dir = out_dir / "results"
    models_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    keep_tokens = ("_L1_", "_L0.1_", "_L0.01_")
    candidate_features = [c for c in df.columns if any(tok in c for tok in keep_tokens)]
    feature_cols, leakage_audit = select_clean_traffic_features(
        df, candidate_features
    )
    leakage_audit.to_csv(results_dir / "stage_a_feature_filter_audit.csv", index=False)
    logger.info(
        "Using %d/%d clean multi-window features for IF training (%d removed)",
        len(feature_cols),
        len(candidate_features),
        int(leakage_audit["remove_for_clean_model"].sum()),
    )

    all_summary = []
    all_per_attack = []

    for device_name, device_df in df.groupby("device_name"):
        logger.info(f"Training IF for {device_name}...")
        model, scaler, metrics = train_one_device(device_df, feature_cols)

        # Persist
        joblib.dump(model, models_dir / f"if_{device_name}.joblib")
        joblib.dump(scaler, models_dir / f"scaler_{device_name}.joblib")

        per_attack_df = metrics.pop("per_attack")
        all_summary.append(metrics)
        all_per_attack.append(per_attack_df)

        logger.info(
            f"  benign FPR={metrics['benign_fpr']:.3f}, "
            f"attack recall={metrics['attack_recall']:.3f}"
        )

    # Also save the feature column list - critical for inference consistency
    joblib.dump(feature_cols, models_dir / "if_feature_cols.joblib")

    summary_df = pd.DataFrame(all_summary)
    per_attack_df = pd.concat(all_per_attack, ignore_index=True)

    summary_df.to_csv(results_dir / "stage_a_summary.csv", index=False)
    per_attack_df.to_csv(results_dir / "stage_a_per_attack.csv", index=False)

    return summary_df, per_attack_df


def print_report(summary_df: pd.DataFrame, per_attack_df: pd.DataFrame) -> None:
    """Pretty-print headline metrics."""
    print("\n=== Stage A per-device summary ===")
    cols = ["device_name", "n_benign_train", "n_attack_test",
            "benign_fpr", "attack_recall"]
    print(summary_df[cols].to_string(index=False))

    print("\n=== Aggregate (weighted by sample count) ===")
    total_benign = summary_df["n_benign_test"].sum()
    total_attack = summary_df["n_attack_test"].sum()
    weighted_fpr = (
        (summary_df["benign_fpr"] * summary_df["n_benign_test"]).sum() / total_benign
    )
    weighted_recall = (
        (summary_df["attack_recall"] * summary_df["n_attack_test"]).sum() / total_attack
    )
    print(f"  Overall benign FPR:    {weighted_fpr:.3f}")
    print(f"  Overall attack recall: {weighted_recall:.3f}")

    print("\n=== Per-attack-type recall (averaged across devices) ===")
    family_summary = (
        per_attack_df.groupby("attack_type")
                     .agg(mean_recall=("recall", "mean"),
                          min_recall=("recall", "min"),
                          max_recall=("recall", "max"),
                          n_devices=("device_name", "nunique"))
                     .sort_values("mean_recall")
    )
    # Force full display - pandas truncates by default
    with pd.option_context("display.max_rows", None, "display.width", 200):
        print(family_summary.to_string())

    # Weakness flags
    weak = per_attack_df[per_attack_df["recall"] < 0.8]
    if len(weak):
        print("\n=== Weak cells (recall < 0.80) ===")
        print(weak.sort_values("recall").to_string(index=False))


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    DATA_PATH = Path("nbaiot_sampled.parquet")
    OUT_DIR = Path(".")

    df = pd.read_parquet(DATA_PATH)
    logger.info(f"Loaded {len(df):,} rows from {DATA_PATH}")

    summary_df, per_attack_df = train_all_devices(df, OUT_DIR)
    print_report(summary_df, per_attack_df)

    print("\nModels saved to ./models/, results to ./results/")
