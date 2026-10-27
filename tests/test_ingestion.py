"""Detection ingestion and the alert mapping."""

import pytest
from conftest import SAMPLES
from connectors.core.connector import ConnectorError


@pytest.mark.op("ingest_ai_detections")
def test_ingest_maps_detections_to_alerts(mock_api, config):
    from crowdstrike_guardian.operations import ingest_ai_detections

    result = ingest_ai_detections(config, {"time_range": "24h"})
    assert result["count"] == 2
    alert = result["alerts"][0]
    assert alert["external_id"] == SAMPLES["detection"]["CompositeId"]
    assert alert["name"] == "AI agent executed an obfuscated command"
    assert alert["severity"] == "High"
    assert alert["alert_state"] == "New"
    assert alert["alert_type"] == "CrowdStrike Guardian"
    assert alert["category"] == "AI Agent Security"
    assert alert["subcategory"] == "Execution"
    assert alert["rule_name"] == "Command and Scripting Interpreter"
    assert alert["alert_generation_epoch"] is not None
    assert alert["falcon_ui_url"].startswith("https://falcon.crowdstrike.com/")
    assert alert["raw_detection"]["CompositeId"] == SAMPLES["detection"]["CompositeId"]


@pytest.mark.op("ingest_ai_detections")
def test_ingest_severity_threshold_filters(mock_api, config):
    from crowdstrike_guardian.operations import ingest_ai_detections

    # fixtures: HIGH (80) and CRITICAL (95); threshold 90 keeps only the 95
    result = ingest_ai_detections(config, {"severity_min": 90})
    assert result["count"] == 1
    assert result["alerts"][0]["severity"] == "Critical"


@pytest.mark.op("ingest_ai_detections")
def test_ingest_maps_states(mock_api, config):
    from crowdstrike_guardian.operations import ingest_ai_detections

    result = ingest_ai_detections(config, {})
    states = {a["raw_detection"]["Status"]: a["alert_state"] for a in result["alerts"]}
    assert states["new"] == "New"
    assert states["in_progress"] == "Open"


@pytest.mark.op("ingest_ai_detections")
def test_ingest_max_records_caps(mock_api, config):
    from crowdstrike_guardian.operations import ingest_ai_detections

    result = ingest_ai_detections(config, {"max_records": 1})
    assert result["count"] == 1


@pytest.mark.op("ingest_ai_detections")
def test_ingest_product_filter(mock_api, config):
    from crowdstrike_guardian.operations import ingest_ai_detections

    result = ingest_ai_detections(config, {"product": "claude code"})
    assert result["count"] == 1
    sent = mock_api.calls_to("/aidr/queries/detections/v1")[0].params
    assert sent["product"] == "CLAUDE_CODE"
    assert sent["time_range"] == "24h"  # ingestion default window


# ---------------------------------------------------------------------------
# field mapping details
# ---------------------------------------------------------------------------


def test_unattributed_detection_maps_cleanly():
    from crowdstrike_guardian.field_mapping import map_detection_to_alert

    alert = map_detection_to_alert(SAMPLES["detection_unattributed"])
    assert alert["agentic_product"] is None
    assert alert["severity"] == "Critical"
    assert alert["alert_state"] == "Open"
    assert alert["falcon_ui_url"] is None


def test_severity_resolution_is_always_a_picklist_value():
    from crowdstrike_guardian.field_mapping import resolve_severity

    assert resolve_severity("CRITICAL") == "Critical"
    assert resolve_severity("informational") == "Minimal"
    assert resolve_severity("SOMETHING-NEW", 85) == "Critical"
    assert resolve_severity(None, 50) == "Medium"
    assert resolve_severity(None, 10) == "Minimal"
    assert resolve_severity(None, None) == "Minimal"
    assert resolve_severity(None, "not-a-number") == "Minimal"


def test_epoch_helper_handles_naive_and_zulu():
    from crowdstrike_guardian.field_mapping import _iso_to_epoch_seconds

    assert _iso_to_epoch_seconds("2026-10-27T00:00:00Z") == _iso_to_epoch_seconds("2026-10-27T00:00:00+00:00")
    assert _iso_to_epoch_seconds("") is None
    assert _iso_to_epoch_seconds("not a date") is None


def test_ingest_rejects_bad_time_range_without_a_request(mock_api, config):
    from crowdstrike_guardian.operations import ingest_ai_detections

    with pytest.raises(ConnectorError):
        ingest_ai_detections(config, {"time_range": "yesterday"})
    assert not mock_api.calls_to("/aidr/queries/detections/v1")
