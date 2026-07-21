"""Contract tests against the real, frozen Module 1 export artifacts."""

from dataclasses import fields

import numpy as np
import pandas as pd
import pytest

from ..config import CLASS_ORDER
from ..contracts import (
    ALERT_COLUMNS,
    Alert,
    load_alerts,
    load_benign_reference_stats,
    load_export_schema,
    load_shap_global_profiles,
)


EXPECTED_DEVICES = {
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


@pytest.fixture(scope="module")
def schema() -> dict:
    return load_export_schema()


@pytest.fixture(scope="module")
def alerts() -> pd.DataFrame:
    return load_alerts()


@pytest.fixture(scope="module")
def probability_matrix(alerts: pd.DataFrame) -> np.ndarray:
    return np.stack(alerts["p_vector"].to_numpy())


def test_alert_columns_match_export_schema(
    alerts: pd.DataFrame, schema: dict
) -> None:
    assert list(alerts.columns) == schema["alerts_full_schema"]


def test_probability_vectors_have_expected_length_and_sum_to_one(
    probability_matrix: np.ndarray,
) -> None:
    assert probability_matrix.shape[1] == 11
    np.testing.assert_allclose(
        probability_matrix.sum(axis=1), 1.0, atol=1e-6, rtol=0.0
    )


def test_pair_probability_and_margin_are_consistent(
    alerts: pd.DataFrame, probability_matrix: np.ndarray
) -> None:
    tcp_index = CLASS_ORDER.index("gafgyt_tcp")
    udp_index = CLASS_ORDER.index("gafgyt_udp")
    expected_pair = (
        probability_matrix[:, tcp_index] + probability_matrix[:, udp_index]
    )
    np.testing.assert_allclose(alerts["p_pair"], expected_pair, atol=1e-6, rtol=0.0)
    np.testing.assert_allclose(
        alerts["margin"], alerts["p_top1"] - alerts["p_top2"], atol=1e-6, rtol=0.0
    )


def test_benign_reference_stats_cover_all_devices() -> None:
    stats = load_benign_reference_stats()
    assert set(stats.index) == EXPECTED_DEVICES


def test_shap_global_profiles_load_and_cover_all_classes() -> None:
    profiles = load_shap_global_profiles()
    assert not profiles.empty
    assert set(profiles["class"]) == set(CLASS_ORDER)


def test_config_class_order_matches_export_schema(schema: dict) -> None:
    assert CLASS_ORDER == tuple(schema["p_vector_class_order"])


def test_alert_from_real_row(alerts: pd.DataFrame) -> None:
    row = alerts.iloc[0]
    alert = Alert.from_row(row)

    assert tuple(field.name for field in fields(Alert)) == ALERT_COLUMNS
    assert alert.sample_id == row["sample_id"]
    assert alert.device_name == row["device_name"]
    assert alert.p_vector == pytest.approx(tuple(row["p_vector"]))
    assert alert.stage_a_flagged == row["stage_a_flagged"]
