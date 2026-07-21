"""
N-BaIoT data loader with stratified sampling and label extraction.

Directory structure expected:
    <root>/
        <device_name>/
            benign_traffic.csv
            mirai_attacks/<variant>.csv    (optional - only 7 devices have this)
            gafgyt_attacks/<variant>.csv   (all 9 devices)

Output: a single tidy DataFrame with columns:
    - 115 feature columns (original N-BaIoT features)
    - device_name: e.g. 'Danmini_Doorbell'
    - label_type:  e.g. 'benign', 'mirai_ack', 'gafgyt_combo'
    - label_binary: 0 for benign, 1 for any attack
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd

logger = logging.getLogger(__name__)

# Devices that only have Gafgyt attacks (no Mirai subfolder)
GAFGYT_ONLY_DEVICES = {"Samsung_SNH_1011_N_Webcam", "Ennio_Doorbell"}


def _read_csv_with_sample(
    path: Path,
    n_sample: Optional[int],
    random_state: int,
) -> pd.DataFrame:
    """Read a CSV and optionally subsample it. Returns empty DataFrame if file missing."""
    if not path.exists():
        logger.warning(f"Missing file: {path}")
        return pd.DataFrame()

    df = pd.read_csv(path)
    if n_sample is not None and len(df) > n_sample:
        df = df.sample(n=n_sample, random_state=random_state).reset_index(drop=True)
    return df


def load_device_data(
    device_dir: Path,
    n_per_cell: Optional[int] = 5000,
    random_state: int = 42,
) -> pd.DataFrame:
    """
    Load all traffic data for a single device, with stratified sampling per cell.

    A "cell" is one (device, label_type) combination, e.g. (Danmini_Doorbell, mirai_ack).
    """
    device_name = device_dir.name
    frames: list[pd.DataFrame] = []

    # Benign traffic
    benign_path = device_dir / "benign_traffic.csv"
    df_benign = _read_csv_with_sample(benign_path, n_per_cell, random_state)
    if not df_benign.empty:
        df_benign["device_name"] = device_name
        df_benign["label_type"] = "benign"
        df_benign["label_binary"] = 0
        frames.append(df_benign)

    # Mirai attacks (only for devices that have them)
    if device_name not in GAFGYT_ONLY_DEVICES:
        mirai_dir = device_dir / "mirai_attacks"
        if mirai_dir.exists():
            for csv_path in sorted(mirai_dir.glob("*.csv")):
                variant = csv_path.stem  # 'ack', 'scan', 'syn', 'udp', 'udpplain'
                df = _read_csv_with_sample(csv_path, n_per_cell, random_state)
                if df.empty:
                    continue
                df["device_name"] = device_name
                df["label_type"] = f"mirai_{variant}"
                df["label_binary"] = 1
                frames.append(df)
        else:
            logger.warning(f"Expected mirai_attacks dir not found for {device_name}")

    # Gafgyt attacks (all devices)
    gafgyt_dir = device_dir / "gafgyt_attacks"
    if gafgyt_dir.exists():
        for csv_path in sorted(gafgyt_dir.glob("*.csv")):
            variant = csv_path.stem  # 'combo', 'junk', 'scan', 'tcp', 'udp'
            df = _read_csv_with_sample(csv_path, n_per_cell, random_state)
            if df.empty:
                continue
            df["device_name"] = device_name
            df["label_type"] = f"gafgyt_{variant}"
            df["label_binary"] = 1
            frames.append(df)
    else:
        logger.warning(f"Expected gafgyt_attacks dir not found for {device_name}")

    if not frames:
        logger.error(f"No data loaded for device {device_name}")
        return pd.DataFrame()

    return pd.concat(frames, ignore_index=True)


def load_nbaiot(
    root_dir: str | Path,
    n_per_cell: Optional[int] = 5000,
    random_state: int = 42,
    devices: Optional[list[str]] = None,
) -> pd.DataFrame:
    """
    Load the full N-BaIoT dataset with stratified sampling.

    Args:
        root_dir: Path to extracted N-BaIoT root containing device folders.
        n_per_cell: Max rows per (device, label_type) cell. None = load all.
        random_state: Random seed for sampling reproducibility.
        devices: Optional whitelist of device names to load. None = all.

    Returns:
        Tidy DataFrame with 115 features + device_name + label_type + label_binary.
    """
    root = Path(root_dir)
    if not root.exists():
        raise FileNotFoundError(f"Root directory does not exist: {root}")

    # Find device directories (subdirs that contain benign_traffic.csv)
    device_dirs = sorted(
        d for d in root.iterdir()
        if d.is_dir() and (d / "benign_traffic.csv").exists()
    )

    if devices is not None:
        device_dirs = [d for d in device_dirs if d.name in devices]

    if not device_dirs:
        raise ValueError(f"No device directories found under {root}")

    logger.info(f"Found {len(device_dirs)} device directories")

    frames = []
    for device_dir in device_dirs:
        logger.info(f"Loading {device_dir.name}...")
        df = load_device_data(device_dir, n_per_cell, random_state)
        if not df.empty:
            frames.append(df)
            logger.info(f"  -> {len(df):,} rows")

    full = pd.concat(frames, ignore_index=True)

    # Sanity: feature columns should be everything except the 3 meta columns
    meta_cols = ["device_name", "label_type", "label_binary"]
    feature_cols = [c for c in full.columns if c not in meta_cols]
    logger.info(f"Loaded total: {len(full):,} rows, {len(feature_cols)} features")

    return full


def summarize(df: pd.DataFrame) -> pd.DataFrame:
    """Print a cell-level summary of the loaded data."""
    summary = (
        df.groupby(["device_name", "label_type"])
          .size()
          .unstack(fill_value=0)
          .sort_index()
    )
    return summary


def select_l1_features(df: pd.DataFrame) -> list[str]:
    """Return the 1.5-second time-window feature columns for Isolation Forest."""
    return [c for c in df.columns if "_L1_" in c]


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s",
    )

    # Adjust this to your extracted location
    ROOT = r"D:\LLM\N-BaIoT"

    df = load_nbaiot(ROOT, n_per_cell=5000, random_state=42)

    print("\n=== Cell counts (rows per device x label_type) ===")
    print(summarize(df))

    print("\n=== Overall label balance ===")
    print(df["label_binary"].value_counts())

    print("\n=== L1 (1.5s window) feature count ===")
    l1_feats = select_l1_features(df)
    print(f"  {len(l1_feats)} features selected for IF training")
    print(f"  Examples: {l1_feats[:5]}")

    # Save for downstream use
    out_path = Path("nbaiot_sampled.parquet")
    df.to_parquet(out_path, index=False)
    print(f"\nSaved to {out_path.resolve()}")