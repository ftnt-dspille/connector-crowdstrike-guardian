"""info.json is consistent with the code and with what the step editor needs."""

import json
import re
import runpy
from pathlib import Path

import pytest
from connectors.core.connector import ConnectorError

from crowdstrike_guardian.operations import operations

ROOT = Path(__file__).resolve().parent.parent
INFO = json.load(open(ROOT / "crowdstrike_guardian" / "info.json"))
OPS = {o["operation"]: o for o in INFO["operations"]}
TYPES = {"text", "textarea", "integer", "checkbox", "select", "json", "datetime", "password", "multiselect"}


def test_info_json_is_what_the_generator_produces():
    generated = runpy.run_path(str(ROOT / "scripts" / "gen_info.py"))["build"]()
    assert generated == INFO, "info.json is stale: run python3 scripts/gen_info.py"


def test_info_operations_match_the_code():
    assert set(OPS) == set(operations)
    assert len(INFO["operations"]) == len(OPS), "duplicate operation in info.json"


def test_connector_identity():
    assert INFO["name"] == "crowdstrike_guardian"
    assert re.match(r"^\d+\.\d+\.\d+$", INFO["version"])
    assert (ROOT / "crowdstrike_guardian" / "images" / INFO["icon_small_name"]).exists()
    assert (ROOT / "crowdstrike_guardian" / "images" / INFO["icon_large_name"]).exists()


def test_release_notes_cover_the_current_version():
    assert (
        "#### {}".format(INFO["version"]) in (ROOT / "crowdstrike_guardian" / "release_notes.md").read_text()
    )


def test_ingestion_is_declared():
    assert INFO["ingestion_supported"] is True
    assert "scheduled" in INFO["ingestion_modes"]
    assert "ingest_ai_detections" in OPS


def test_every_endpoint_the_connector_calls_is_declared_in_constants():
    from crowdstrike_guardian.constants import ENDPOINTS
    from crowdstrike_guardian.operations import ROUTES

    assert ROUTES is ENDPOINTS


@pytest.mark.parametrize("name", sorted(OPS))
def test_operation_definition_is_complete(name):
    op = OPS[name]
    assert op["title"] and op["description"]
    assert op["annotation"] == name
    assert op["enabled"] is True
    assert op["category"] in ("investigation", "remediation", "containment", "miscellaneous")
    seen = set()
    for param in op["parameters"]:
        assert param["name"] not in seen, "duplicate parameter {}".format(param["name"])
        seen.add(param["name"])
        assert param["type"] in TYPES, param
        assert param["title"] and param["description"]
        if param["type"] == "select" and not param.get("apiOperation"):
            assert param.get("options"), "{}.{} is a select with no options".format(name, param["name"])
            if "value" in param:
                values = [o["value"] if isinstance(o, dict) else o for o in param["options"]]
                assert param["value"] in values
        if param.get("apiOperation"):
            assert param["apiOperation"] in OPS, param
            assert OPS[param["apiOperation"]].get("visible") is False
            assert not OPS[param["apiOperation"]]["parameters"], "populators receive only the config"


def test_hidden_operations_stay_off_the_palette():
    assert OPS["list_ai_product_options"]["visible"] is False
    assert all(op["visible"] for name, op in OPS.items() if name != "list_ai_product_options")


def test_configuration_fields():
    fields = {f["name"]: f for f in INFO["configuration"]["fields"]}
    assert {"cloud", "client_id", "client_secret", "timeout", "verify_ssl"} <= set(fields)
    assert fields["client_secret"]["type"] == "password"
    assert fields["client_id"]["type"] != "password"
    cloud = fields["cloud"]
    assert cloud["type"] == "select"
    values = [o["value"] for o in cloud["options"]]
    assert cloud["value"] in values
    # Pattern A: picking Custom reveals the base URL field
    assert "custom" in cloud["onchange"]
    child = cloud["onchange"]["custom"][0]
    assert child["name"] == "base_url" and child["required"] is True


@pytest.mark.parametrize("name", sorted(OPS))
def test_every_required_parameter_is_enforced_by_the_code(name, config, mock_api):
    """Leaving a required parameter out must fail fast, before any request."""
    required = [p["name"] for p in OPS[name]["parameters"] if p.get("required")]
    for missing in required:
        params = {p: "x" for p in required if p != missing}
        with pytest.raises(ConnectorError) as excinfo:
            operations[name](config, params)
        assert "required" in str(excinfo.value), (name, missing)
        assert not mock_api.calls, f"{name}.{missing}: made a request without a required parameter"
