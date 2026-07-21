"""
Stage B: Global XGBoost classifier for attack type prediction.

Design:
  - One global model, all 115 features, device_name encoded as categorical.
  - 11 classes: benign + 10 attack types (5 mirai + 5 gafgyt).
  - Trained on all data (not just Stage-A-flagged) for sample efficiency.
  - Calibrated with isotonic regression on a held-out set.
  - Evaluated TWO ways:
      A) Standalone: XGBoost predictions on full test set (lab metric).
      B) Stage-A-gated: only on samples Stage A flags (deployment metric).

Outputs:
  - models/xgb_stage_b.joblib              : calibrated classifier
  - models/xgb_label_encoder.joblib        : label name <-> class index mapping
  - models/xgb_feature_cols.joblib         : feature column order (critical!)
  - results/stage_b_standalone_report.csv  : classification report (lab)
  - results/stage_b_gated_report.csv       : classification report (deployment)
  - results/stage_b_confusion_gated.csv    : confusion matrix on gated samples
  - results/stage_b_threshold_sweep.csv    : confidence threshold analysis
"""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

from leakage_filters import select_clean_traffic_features

logger = logging.getLogger(__name__)

RANDOM_STATE = 42

# Splits: train -> fit XGBoost
#         calib -> fit isotonic calibrator on top
#         test  -> final evaluation, never seen during training/calibration
TEST_FRACTION = 0.20
CALIB_FRACTION = 0.15  # of the remaining 80% after test split

XGB_PARAMS = dict(
    n_estimators=400,
    max_depth=6,
    learning_rate=0.1,
    objective="multi:softprob",
    eval_metric="mlogloss",
    n_jobs=-1,
    random_state=RANDOM_STATE,
    tree_method="hist",   # fast, CPU-friendly
)


# ---------------------------------------------------------------------------
# Stage A inference helper (mirrors what production would do)
# ---------------------------------------------------------------------------

def run_stage_a_on_test(
    test_df: pd.DataFrame,
    models_dir: Path,
) -> np.ndarray:
    """
    Apply each device's IF + scaler to the test rows and return a boolean
    array: True = Stage A flagged as anomaly.
    """
    if_features = joblib.load(models_dir / "if_feature_cols.joblib")

    flagged = np.zeros(len(test_df), dtype=bool)

    # Process device-by-device using the .index to write back into the array
    for device_name, grp in test_df.groupby("device_name"):
        model_path = models_dir / f"if_{device_name}.joblib"
        scaler_path = models_dir / f"scaler_{device_name}.joblib"
        if not model_path.exists():
            logger.warning(f"No Stage A model for {device_name}, treating all as flagged")
            flagged[grp.index] = True
            continue

        model = joblib.load(model_path)
        scaler = joblib.load(scaler_path)

        X = scaler.transform(grp[if_features].values)
        preds = model.predict(X)  # -1 = anomaly, +1 = inlier
        flagged[grp.index] = (preds == -1)

    return flagged


# ---------------------------------------------------------------------------
# Feature preparation for Stage B
# ---------------------------------------------------------------------------

def prepare_features(df: pd.DataFrame) -> tuple[pd.DataFrame, list[str]]:
    """
    Build the Stage B feature matrix:
      - original traffic features after timestamp-leakage filtering
      - device_name one-hot encoded (9 dummy columns)

    Returns:
        X: DataFrame of features
        feature_cols: ordered column names (must match at inference time)
    """
    meta_cols = {"device_name", "label_type", "label_binary"}
    candidate_features = [c for c in df.columns if c not in meta_cols]
    traffic_features, _ = select_clean_traffic_features(df, candidate_features)

    # One-hot device. drop_first=False keeps all 9 so inference is order-agnostic.
    device_dummies = pd.get_dummies(df["device_name"], prefix="dev")

    X = pd.concat(
        [df[traffic_features].reset_index(drop=True),
         device_dummies.reset_index(drop=True)],
        axis=1,
    )
    feature_cols = list(X.columns)
    return X, feature_cols


# ---------------------------------------------------------------------------
# Training
# ---------------------------------------------------------------------------

def train_stage_b(
    df: pd.DataFrame,
    out_dir: Path,
) -> dict:
    """
    Full Stage B pipeline: split, train, calibrate, evaluate (both standalone
    and Stage-A-gated), save artefacts.
    """
    models_dir = out_dir / "models"
    results_dir = out_dir / "results"
    models_dir.mkdir(parents=True, exist_ok=True)
    results_dir.mkdir(parents=True, exist_ok=True)

    # ---- Encode labels ----
    le = LabelEncoder()
    y = le.fit_transform(df["label_type"].values)
    logger.info(f"Classes ({len(le.classes_)}): {list(le.classes_)}")

    # ---- Build features ----
    candidate_features = [
        c for c in df.columns if c not in {"device_name", "label_type", "label_binary"}
    ]
    traffic_features, leakage_audit = select_clean_traffic_features(
        df, candidate_features
    )
    leakage_audit.to_csv(results_dir / "stage_b_feature_filter_audit.csv", index=False)
    logger.info(
        "Stage B clean feature filter: kept %d/%d traffic features, removed %d",
        len(traffic_features),
        len(candidate_features),
        int(leakage_audit["remove_for_clean_model"].sum()),
    )

    device_dummies = pd.get_dummies(df["device_name"], prefix="dev")
    X = pd.concat(
        [df[traffic_features].reset_index(drop=True),
         device_dummies.reset_index(drop=True)],
        axis=1,
    )
    feature_cols = list(X.columns)
    logger.info(f"Feature matrix: {X.shape}")

    # Keep device_name + original index so we can run Stage A later
    aux = df[["device_name", "label_type"]].reset_index(drop=True)

    # ---- Three-way split: train / calib / test ----
    # Stratify on label so every class is represented in every split.
    X_trainval, X_test, y_trainval, y_test, aux_trainval, aux_test = train_test_split(
        X, y, aux,
        test_size=TEST_FRACTION,
        stratify=y,
        random_state=RANDOM_STATE,
    )
    X_train, X_calib, y_train, y_calib = train_test_split(
        X_trainval, y_trainval,
        test_size=CALIB_FRACTION,
        stratify=y_trainval,
        random_state=RANDOM_STATE,
    )
    logger.info(
        f"Splits - train: {len(X_train):,}, calib: {len(X_calib):,}, "
        f"test: {len(X_test):,}"
    )

    # ---- Fit base XGBoost ----
    logger.info("Training XGBoost...")
    base = XGBClassifier(**XGB_PARAMS, num_class=len(le.classes_))
    base.fit(X_train, y_train)

    # ---- Calibrate ----
    # cv='prefit' tells sklearn the base estimator is already fit; it only
    # learns the calibration mapping from calib data.
    logger.info("Calibrating with isotonic regression...")
    calibrated = CalibratedClassifierCV(base, method="isotonic", cv="prefit")
    calibrated.fit(X_calib, y_calib)

    # ---- Persist artefacts ----
    joblib.dump(calibrated, models_dir / "xgb_stage_b.joblib")
    joblib.dump(le, models_dir / "xgb_label_encoder.joblib")
    joblib.dump(feature_cols, models_dir / "xgb_feature_cols.joblib")
    logger.info(f"Saved model + encoder + feature columns to {models_dir}")

    # ---- Standalone evaluation (lab metric) ----
    logger.info("\n--- Standalone evaluation (no Stage A gating) ---")
    probs_standalone = calibrated.predict_proba(X_test)
    preds_standalone = probs_standalone.argmax(axis=1)

    standalone_report = classification_report(
        y_test, preds_standalone,
        labels=range(len(le.classes_)),
        target_names=le.classes_,
        output_dict=True,
        zero_division=0,
    )
    pd.DataFrame(standalone_report).T.to_csv(
        results_dir / "stage_b_standalone_report.csv"
    )
    print("\n=== Stage B standalone (lab) classification report ===")
    print(classification_report(
        y_test, preds_standalone,
        labels=range(len(le.classes_)),
        target_names=le.classes_,
        zero_division=0,
    ))

    # Binary ROC-AUC: benign vs anything-attack
    benign_class_idx = list(le.classes_).index("benign")
    y_test_binary = (y_test != benign_class_idx).astype(int)
    attack_prob = 1.0 - probs_standalone[:, benign_class_idx]
    auc = roc_auc_score(y_test_binary, attack_prob)
    print(f"Binary ROC-AUC (benign vs attack): {auc:.4f}")

    # ---- Stage-A-gated evaluation (deployment metric) ----
    logger.info("\n--- Stage-A-gated evaluation (deployment) ---")

    # We need Stage A flags on the test set. Reconstruct a frame with the raw
    # features Stage A expects (it uses its own subset).
    test_with_meta = pd.concat(
        [aux_test.reset_index(drop=True),
         df.loc[aux_test.index].drop(columns=["device_name", "label_type"])
           .reset_index(drop=True)],
        axis=1,
    )
    # Re-index to a clean 0..N-1 range for run_stage_a_on_test
    test_with_meta = test_with_meta.reset_index(drop=True)
    stage_a_flags = run_stage_a_on_test(test_with_meta, models_dir)

    n_total = len(y_test)
    n_flagged = stage_a_flags.sum()
    logger.info(f"Stage A flagged {n_flagged:,} / {n_total:,} test samples "
                f"({n_flagged/n_total:.1%})")

    # How many true attacks did Stage A miss entirely?
    truly_attack = (y_test != benign_class_idx)
    missed_by_stage_a = truly_attack & (~stage_a_flags)
    logger.info(
        f"Stage A missed {missed_by_stage_a.sum():,} true attacks "
        f"({missed_by_stage_a.sum()/truly_attack.sum():.2%} of all attacks). "
        f"These are end-to-end false negatives."
    )

    # Stage B evaluation on flagged subset
    y_test_arr = np.asarray(y_test)
    y_test_gated = y_test_arr[stage_a_flags]
    preds_gated = preds_standalone[stage_a_flags]

    if len(y_test_gated) > 0:
        gated_report = classification_report(
            y_test_gated, preds_gated,
            labels=range(len(le.classes_)),
            target_names=le.classes_,
            output_dict=True,
            zero_division=0,
        )
        pd.DataFrame(gated_report).T.to_csv(
            results_dir / "stage_b_gated_report.csv"
        )
        print("\n=== Stage B Stage-A-gated (deployment) classification report ===")
        print(classification_report(
            y_test_gated, preds_gated,
            labels=range(len(le.classes_)),
            target_names=le.classes_,
            zero_division=0,
        ))

        # Confusion matrix on gated samples
        cm = confusion_matrix(y_test_gated, preds_gated,
                              labels=range(len(le.classes_)))
        cm_df = pd.DataFrame(cm, index=le.classes_, columns=le.classes_)
        cm_df.to_csv(results_dir / "stage_b_confusion_gated.csv")

    # ---- Confidence threshold sweep on standalone test set ----
    # Use max(proba) as confidence. Calibrated, so this is interpretable.
    confidence = probs_standalone.max(axis=1)
    sweep_rows = []
    for tau in np.arange(0.50, 0.96, 0.05):
        mask = confidence >= tau
        if mask.sum() == 0:
            continue
        coverage = mask.mean()
        accuracy = (preds_standalone[mask] == y_test_arr[mask]).mean()
        # Macro-F1 on the high-confidence subset
        try:
            macro_f1 = f1_score(
                y_test_arr[mask], preds_standalone[mask],
                labels=range(len(le.classes_)),
                average="macro", zero_division=0,
            )
        except ValueError:
            macro_f1 = np.nan
        sweep_rows.append({
            "threshold": round(tau, 2),
            "coverage": coverage,
            "accuracy": accuracy,
            "macro_f1": macro_f1,
            "n_samples": int(mask.sum()),
        })
    sweep_df = pd.DataFrame(sweep_rows)
    sweep_df.to_csv(results_dir / "stage_b_threshold_sweep.csv", index=False)
    print("\n=== Confidence threshold sweep (use this to pick triage threshold) ===")
    print(sweep_df.to_string(index=False))

    return {
        "n_train": len(X_train),
        "n_calib": len(X_calib),
        "n_test": len(X_test),
        "n_stage_a_flagged": int(n_flagged),
        "stage_a_missed_attacks": int(missed_by_stage_a.sum()),
        "binary_roc_auc": auc,
    }


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    DATA_PATH = Path("nbaiot_sampled.parquet")
    OUT_DIR = Path(".")

    df = pd.read_parquet(DATA_PATH)
    logger.info(f"Loaded {len(df):,} rows")

    summary = train_stage_b(df, OUT_DIR)
    print("\n=== Run summary ===")
    for k, v in summary.items():
        print(f"  {k}: {v}")
