"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

PACKAGE = pathlib.Path(__file__).resolve().parents[1] / "crowdstrike_guardian"
INFO = json.loads((PACKAGE / "info.json").read_text())
COMPILED = json.loads((PACKAGE / "playbooks" / "playbooks.json").read_text())

FETCH_NAME = "> CrowdStrike Guardian > Fetch"
INGEST_NAME = "CrowdStrike Guardian > Ingest"


def _collection():
    return COMPILED["data"][0]


def _workflows():
    return {wf["name"]: wf for wf in _collection()["workflows"]}


def _steps(workflow):
    return {step["name"]: step for step in workflow["steps"]}


def _guardian_steps():
    """Every compiled connector step that calls this connector."""
    for wf in _collection()["workflows"]:
        for step in wf["steps"]:
            args = step.get("arguments") or {}
            if args.get("connector") == INFO["name"]:
                yield wf["name"], step


def test_collection_name_carries_the_info_version():
    # FortiSOAR deletes and re-imports the sample collection by name on
    # connector upgrade, so the compiled collection name must track
    # info.json's version (the release CI refuses a mismatch too).
    name = _collection()["name"]
    assert re.search(re.escape(INFO["version"]) + r"$", name), name


def test_wizard_discovery_tags():
    # The Data Ingestion Wizard filters workflow collections on
    # recordTags=dataingestion and the connector's exported_tags before it
    # will offer an ingestion configuration.
    collection = _collection()
    assert INFO["name"] in collection["recordTags"]
    assert "dataingestion" in collection["recordTags"]
    exported = set(COMPILED["exported_tags"])
    assert {"dataingestion", "fetch", "create", "ingest"} <= exported


def test_connector_steps_call_registered_operations_with_declared_params():
    from crowdstrike_guardian import operations as ops_module

    declared = {op["operation"]: {p["name"] for p in op["parameters"]} for op in INFO["operations"]}
    checked = 0
    for wf_name, step in _guardian_steps():
        operation = step["arguments"]["operation"]
        assert operation in ops_module.operations, f"{wf_name} calls unregistered {operation}"
        assert operation in declared, f"{wf_name} calls undeclared {operation}"
        params = step["arguments"].get("params") or {}
        unknown = set(params) - declared[operation]
        assert not unknown, f"{wf_name} passes params {sorted(unknown)} that {operation} does not declare"
        checked += 1
    assert checked >= 5  # the investigation playbooks plus the fetch step


def test_fetch_carries_the_wizard_configuration_schema():
    steps = _steps(_workflows()[FETCH_NAME])
    schema = json.loads(steps["Start"]["arguments"]["step_variables"]["_configuration_schema"])
    fields = {field["name"] for field in schema}
    assert {"cold_start_hours", "product", "agent_id", "severity_min", "max_records"} <= fields


def test_no_step_named_fetch_breaks_the_wizard_scan():
    # prepareFetchSampleConfig treats a step named "fetch" (case-insensitive)
    # as the operation source and stops scanning there, which would render the
    # raw connector params instead of the Start step's configuration schema.
    fetch = _workflows()[FETCH_NAME]
    assert not any(step["name"].strip().lower() == "fetch" for step in fetch["steps"])


def test_ingest_upserts_alerts_via_a_create_record_step():
    # The wizard shows its Data Mapping page only when the create playbook has
    # a step named exactly "Create Record", and reads the target module off it.
    steps = _steps(_workflows()[INGEST_NAME])
    create = steps["Create Record"]
    args = create["arguments"]
    assert args["collection"] == "/api/3/upsert/alerts"
    fields = args["resource"]
    for field in (
        "name",
        "source",
        "sourceId",
        "severity",
        "status",
        "type",
        "alertDetectionDate",
        "eventTime",
        "description",
    ):
        assert field in fields, f"Create Record does not write {field}"
    assert fields["source"] == "CrowdStrike Falcon Guardian"


def test_ingest_reads_the_fetch_contract_back():
    # Fetch publishes its result plus the carry-through vars on "Save Result";
    # Ingest reads them off the workflow_reference step ("List Detections").
    fetch_save = _steps(_workflows()[FETCH_NAME])["Save Result"]["arguments"]
    assert set(fetch_save) == {"data", "current_time", "GuardianMacroName"}
    ingest_cfg = _steps(_workflows()[INGEST_NAME])["Configuration"]["arguments"]
    assert ingest_cfg["incident_source_data"] == "{{ vars.steps.List_Detections.data.alerts }}"
    assert ingest_cfg["current_time"] == "{{ vars.steps.List_Detections.current_time }}"
    assert ingest_cfg["GuardianMacroName"] == "{{ vars.steps.List_Detections.GuardianMacroName }}"


def test_picklist_maps_cover_every_value_field_mapping_emits():
    # An unmapped value makes resolveRange miss and the alert POST fail with a
    # picklist 400. field_mapping and the playbook's maps have to change
    # together; this is the guard that catches one changing alone.
    from crowdstrike_guardian import field_mapping

    ingest_cfg = _steps(_workflows()[INGEST_NAME])["Configuration"]["arguments"]
    severity_keys = set(re.findall(r"'([^']+)':", ingest_cfg["alerts_severity_map"]))
    status_keys = set(re.findall(r"'([^']+)':", ingest_cfg["alerts_status_map"]))
    type_keys = set(re.findall(r"'([^']+)':", ingest_cfg["alerts_type_map"]))

    emitted_severities = set(field_mapping.SEVERITY_MAP.values())
    emitted_severities |= {label for _, label in field_mapping.SEVERITY_NUMERIC_BUCKETS}
    assert emitted_severities <= severity_keys
    assert set(field_mapping.STATUS_MAP.values()) <= status_keys

    # Map a representative detection and require its exact label values to be
    # covered too -- this catches a new alert_type/severity/state literal even
    # if it enters through a code path the constant tables above miss.
    alert = field_mapping.map_detection_to_alert(
        {
            "Name": "Sample detection",
            "CompositeId": "cmp-1",
            "Timestamp": "2026-01-01T00:00:00Z",
            "CreatedTimestamp": "2026-01-01T00:05:00Z",
            "SeverityName": "HIGH",
            "Status": "new",
        }
    )
    assert alert["severity"] in severity_keys
    assert alert["alert_state"] in status_keys
    assert alert["alert_type"] in type_keys


def test_compiled_playbooks_are_fresh():
    """The committed playbooks.json must match playbooks.yaml.

    Runs the real compiler when fsrpb is on PATH; CI (which has no compiler)
    skips this and relies on the version check in the release workflow.
    SOURCE_DATE_EPOCH is pinned to the stamp already in the committed file, so
    an unchanged YAML recompiles byte-identically.
    """
    fsrpb = shutil.which("fsrpb")
    if not fsrpb:
        pytest.skip("fsrpb not on PATH")
    committed = (PACKAGE / "playbooks" / "playbooks.json").read_bytes()
    stamp = COMPILED["data"][0]["workflows"][0]["lastModifyDate"]
    env = dict(os.environ, SOURCE_DATE_EPOCH=str(stamp))
    proc = subprocess.run(
        [sys.executable, str(PACKAGE / "playbooks" / "build.py"), "--fsrpb", fsrpb],
        capture_output=True,
        text=True,
        env=env,
    )
    rebuilt = (PACKAGE / "playbooks" / "playbooks.json").read_bytes()
    (PACKAGE / "playbooks" / "playbooks.json").write_bytes(committed)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert rebuilt == committed, (
        "playbooks.json is stale -- run: python3 crowdstrike_guardian/playbooks/build.py"
    )
