"""Agentic graph, detections, aggregates, inventory, dropdown and dispatch."""

import json

import pytest
from conftest import AID, SAMPLES, SESSION_UUID
from connectors.core.connector import ConnectorError

# ---------------------------------------------------------------------------
# agentic graph
# ---------------------------------------------------------------------------


@pytest.mark.op("get_session_activity")
def test_session_activity_passes_ids(mock_api, config):
    from crowdstrike_guardian.operations import get_session_activity

    result = get_session_activity(config, {"ids": SESSION_UUID})
    assert result["count"] == 1
    assert result["records"][0]["edges"]
    sent = mock_api.calls_to("/aidr/entities/session-activity/v1")[0].params
    assert sent["ids"] == [SESSION_UUID]


@pytest.mark.op("get_session_activity")
def test_session_activity_accepts_vertex_keys(mock_api, config):
    from crowdstrike_guardian.operations import get_session_activity

    vertex = f"aisess:{AID}:{SESSION_UUID}"
    get_session_activity(config, {"ids": vertex})
    sent = mock_api.calls_to("/aidr/entities/session-activity/v1")[-1].params
    assert sent["ids"] == [vertex]


@pytest.mark.op("get_process_tree")
def test_process_tree_depth(mock_api, config):
    from crowdstrike_guardian.operations import get_process_tree

    result = get_process_tree(config, {"session_id": SESSION_UUID, "depth": 3})
    assert result["records"][0]["root"]["name"] == "claude"
    sent = mock_api.calls_to("/aidr/entities/process-tree/v1")[0].params
    assert sent["depth"] == 3


@pytest.mark.op("get_process_tree")
def test_process_tree_depth_out_of_range(mock_api, config):
    from crowdstrike_guardian.operations import get_process_tree

    with pytest.raises(ConnectorError):
        get_process_tree(config, {"session_id": SESSION_UUID, "depth": 9})


@pytest.mark.op("get_network_events")
def test_network_events(mock_api, config):
    from crowdstrike_guardian.operations import get_network_events

    result = get_network_events(config, {"session_id": SESSION_UUID})
    assert result["records"][0]["events"][0]["domain_name"] == "api.anthropic.com"


@pytest.mark.op("get_network_events")
def test_network_events_requires_session(mock_api, config):
    from crowdstrike_guardian.operations import get_network_events

    with pytest.raises(ConnectorError):
        get_network_events(config, {})


@pytest.mark.op("get_file_events")
def test_file_events(mock_api, config):
    from crowdstrike_guardian.operations import get_file_events

    result = get_file_events(config, {"session_id": SESSION_UUID})
    assert result["records"][0]["events"][0]["path"].endswith("app.py")


@pytest.mark.op("get_file_events")
def test_file_events_unknown_session_is_empty(mock_api, config):
    from crowdstrike_guardian.operations import get_file_events

    mock_api.route("GET", "/aidr/entities/file-events/v1", resources=[])
    result = get_file_events(config, {"session_id": "nope"})
    assert result["count"] == 0


@pytest.mark.op("get_classified_file_access")
def test_classified_file_access(mock_api, config):
    from crowdstrike_guardian.operations import get_classified_file_access

    result = get_classified_file_access(config, {"process_id": f"pid:{AID}:4242"})
    assert result["records"][0]["accesses"][0]["classification"] == "Sensitive"


@pytest.mark.op("get_classified_file_access")
def test_classified_file_access_requires_process_id(mock_api, config):
    from crowdstrike_guardian.operations import get_classified_file_access

    with pytest.raises(ConnectorError) as excinfo:
        get_classified_file_access(config, {})
    assert "process_id" in str(excinfo.value)


# ---------------------------------------------------------------------------
# detections
# ---------------------------------------------------------------------------


@pytest.mark.op("list_ai_detections")
def test_list_ai_detections(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_detections

    result = list_ai_detections(config, {"agent_id": AID})
    assert result["count"] == 2
    top = result["records"][0]
    assert top["SeverityName"] == "HIGH"
    assert top["Severity"] == 80
    assert top["falcon_ui_url"].startswith("https://falcon.crowdstrike.com/")
    assert SESSION_UUID not in top["falcon_ui_url"]


@pytest.mark.op("list_ai_detections")
def test_list_ai_detections_agent_id_takes_the_sensor_id(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_detections

    list_ai_detections(config, {"agent_id": AID})
    sent = mock_api.calls_to("/aidr/queries/detections/v1")[0].params
    assert sent["agent_id"] == AID


@pytest.mark.op("list_ai_detections")
def test_list_ai_detections_product_filter(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_detections

    result = list_ai_detections(config, {"product": "claude code"})
    assert result["count"] == 1
    sent = mock_api.calls_to("/aidr/queries/detections/v1")[0].params
    assert sent["product"] == "CLAUDE_CODE"


@pytest.mark.op("get_detection_scores")
def test_detection_scores_rows(mock_api, config):
    from crowdstrike_guardian.operations import get_detection_scores

    result = get_detection_scores(config, {"agent_id": AID})
    rows = {r["product_tag"]: r["max_detection_score"] for r in result["records"]}
    assert rows["213584428666221"] == 80
    assert rows[""] == 95  # unattributed (tag 0) is kept, spelled empty
    assert result["records"][0]["agent_id"] == AID


@pytest.mark.op("get_detection_scores")
def test_detection_scores_truncation_notice(mock_api, config):
    from crowdstrike_guardian.operations import get_detection_scores

    mock_api.route(
        "GET",
        "/aidr/aggregates/detections/v1",
        resources=[{"AgentId": AID, "AgenticProductTag": 0, "maxDetectionScore": "50"}] * 500,
    )
    result = get_detection_scores(config, {})
    assert any("500" in n for n in result["notices"])


# ---------------------------------------------------------------------------
# aggregates and inventory
# ---------------------------------------------------------------------------


@pytest.mark.op("get_agent_product_counts")
def test_agent_product_counts_coerce_strings(mock_api, config):
    from crowdstrike_guardian.operations import get_agent_product_counts

    result = get_agent_product_counts(config, {})
    rows = {r["product"]: r["count"] for r in result["records"]}
    assert rows["Claude Code"] == 3  # arrived as "3"
    assert rows["Cursor"] == 2
    assert "" in rows  # unattributed bucket (tag 0, no friendly name)


@pytest.mark.op("get_agent_product_counts")
def test_agent_product_counts_passes_window(mock_api, config):
    from crowdstrike_guardian.operations import get_agent_product_counts

    get_agent_product_counts(config, {"time_range": "30d"})
    sent = mock_api.calls_to("/aidr/aggregates/agents/v1")[0].params
    assert sent["time_range"] == "30d"


@pytest.mark.op("get_session_product_counts")
def test_session_product_counts(mock_api, config):
    from crowdstrike_guardian.operations import get_session_product_counts

    result = get_session_product_counts(config, {})
    rows = {r["product"]: r["count"] for r in result["records"]}
    assert rows["Claude Code"] == 7
    assert rows["Cursor"] == 4


@pytest.mark.op("get_session_product_counts")
def test_session_product_counts_product_filter(mock_api, config):
    from crowdstrike_guardian.operations import get_session_product_counts

    get_session_product_counts(config, {"product": "Cursor"})
    sent = mock_api.calls_to("/aidr/aggregates/agent-sessions/v1")[0].params
    assert sent["product"] == "CURSOR"


@pytest.mark.op("get_tool_name_counts")
def test_tool_name_counts(mock_api, config):
    from crowdstrike_guardian.operations import get_tool_name_counts

    result = get_tool_name_counts(config, {})
    assert result["records"][0] == {"tool": "Bash", "count": 42}


@pytest.mark.op("get_tool_name_counts")
def test_tool_name_counts_scoped_to_host(mock_api, config):
    from crowdstrike_guardian.operations import get_tool_name_counts

    get_tool_name_counts(config, {"sensor_id": AID})
    sent = mock_api.calls_to("/aidr/aggregates/tools/v1")[0].params
    assert sent["sensor_id"] == AID


@pytest.mark.op("get_skill_name_counts")
def test_skill_name_counts(mock_api, config):
    from crowdstrike_guardian.operations import get_skill_name_counts

    result = get_skill_name_counts(config, {"name_filter": "review"})
    assert result["records"] == [{"skill": "code-review", "count": 5}]
    sent = mock_api.calls_to("/aidr/aggregates/skills/v1")[0].params
    assert sent["name_filter"] == "review"


@pytest.mark.op("get_skill_name_counts")
def test_skill_name_counts_all(mock_api, config):
    from crowdstrike_guardian.operations import get_skill_name_counts

    assert get_skill_name_counts(config, {})["count"] == 1


@pytest.mark.op("get_tool_usage_counts")
def test_tool_usage_counts(mock_api, config):
    from crowdstrike_guardian.operations import get_tool_usage_counts

    result = get_tool_usage_counts(config, {"aid": AID})
    assert {r["tool"]: r["count"] for r in result["records"]} == {"Bash": 17, "Read": 9}
    sent = mock_api.calls_to("/aidr/aggregates/tool-usage/v1")[0].params
    assert sent["time_range"] == "2h"


@pytest.mark.op("get_tool_usage_counts")
def test_tool_usage_counts_session_scope(mock_api, config):
    from crowdstrike_guardian.operations import get_tool_usage_counts

    get_tool_usage_counts(config, {"session_id": SESSION_UUID})
    sent = mock_api.calls_to("/aidr/aggregates/tool-usage/v1")[0].params
    assert sent["session_id"] == SESSION_UUID


@pytest.mark.op("get_skill_usage_counts")
def test_skill_usage_counts(mock_api, config):
    from crowdstrike_guardian.operations import get_skill_usage_counts

    result = get_skill_usage_counts(config, {"aid": AID})
    assert result["records"] == [{"skill": "code-review", "count": 3}]


@pytest.mark.op("get_skill_usage_counts")
def test_skill_usage_counts_window(mock_api, config):
    from crowdstrike_guardian.operations import get_skill_usage_counts

    get_skill_usage_counts(config, {"time_range": "7d"})
    sent = mock_api.calls_to("/aidr/aggregates/skill-usage/v1")[0].params
    assert sent["time_range"] == "7d"


@pytest.mark.op("get_fleet_inventory")
def test_fleet_inventory_rollup(mock_api, config):
    from crowdstrike_guardian.operations import get_fleet_inventory

    result = get_fleet_inventory(config, {"time_range": "7d"})
    assert result["time_range"] == "7d"
    assert {"name": "Claude Code", "count": 3} in result["agents_by_product"]
    assert {"name": "Claude Code", "count": 7} in result["sessions_by_product"]
    assert result["tools_by_name"][0] == {"name": "Bash", "count": 42}
    assert result["detections"]["max_detection_score"] == 95
    assert result["detections"]["truncated"] is False
    # five aggregate routes, one call each
    assert len([c for c in mock_api.calls if c.path.startswith("/aidr/aggregates/")]) == 5


@pytest.mark.op("get_fleet_inventory")
def test_fleet_inventory_sorts_descending(mock_api, config):
    from crowdstrike_guardian.operations import get_fleet_inventory

    result = get_fleet_inventory(config, {})
    counts = [row["count"] for row in result["agents_by_product"]]
    assert counts == sorted(counts, reverse=True)


@pytest.mark.op("get_fleet_inventory")
def test_fleet_inventory_surfaces_notices(mock_api, config):
    from crowdstrike_guardian.operations import get_fleet_inventory

    mock_api.route("GET", "/aidr/aggregates/agents/v1", resources=[{"AgentProduct": 0, "count": "1"}] * 500)
    result = get_fleet_inventory(config, {})
    assert any("500" in n for n in result["notices"])


# ---------------------------------------------------------------------------
# dropdown populator + dispatch
# ---------------------------------------------------------------------------


@pytest.mark.op("list_ai_product_options")
def test_product_options_are_plain_strings(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_product_options

    options = list_ai_product_options(config, {})
    assert options == ["Claude Code", "Cursor"]  # sorted, no objects


@pytest.mark.op("list_ai_product_options")
def test_product_options_skip_unresolved_tags(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_product_options

    options = list_ai_product_options(config, {})
    assert not any(option == "0" or option.isdigit() for option in options)


def test_dispatch_rejects_unknown_operations(config):
    from crowdstrike_guardian.connector import CrowdStrikeGuardian

    connector = CrowdStrikeGuardian()
    try:
        connector.execute(config, "no_such_operation", {})
    except ConnectorError as excinfo:
        assert "Unsupported operation" in str(excinfo)
    else:
        raise AssertionError("expected ConnectorError")


def test_connector_wraps_unexpected_failures(mock_api, config):
    from crowdstrike_guardian.connector import CrowdStrikeGuardian

    def boom(method, url, **kwargs):
        raise RuntimeError("socket exploded")

    import crowdstrike_guardian.client as client_mod

    original = client_mod.requests.request
    client_mod.requests.request = boom
    try:
        connector = CrowdStrikeGuardian()
        with pytest.raises(ConnectorError) as excinfo:
            connector.execute(config, "list_ai_agents", {})
        assert "list_ai_agents failed" in str(excinfo.value)
    finally:
        client_mod.requests.request = original


def test_connector_health(mock_api, config):
    from crowdstrike_guardian.connector import CrowdStrikeGuardian

    assert CrowdStrikeGuardian().check_health(config) is True


def test_health_failure_is_a_connector_error(mock_api, config):
    from crowdstrike_guardian.connector import CrowdStrikeGuardian

    mock_api.route_error(
        "GET", "/aidr/queries/agents/v1", 403, "Client not authorized for AIDR scope", code=403
    )
    with pytest.raises(ConnectorError) as excinfo:
        CrowdStrikeGuardian().check_health(config)
    assert "AIDR" in str(excinfo.value)


def test_every_declared_operation_is_reachable(mock_api, config):
    """Smoke every info.json operation end to end against the fake API.

    Required params are filled from the fixtures; the two spots where the
    generic fill would be wrong (get_ai_agent wants the opaque Id, not the
    sensor id; get_os_user wants the alice fixture user) are overridden.
    """
    from crowdstrike_guardian.operations import operations, resolve_dropdowns

    info = json.load(open("crowdstrike_guardian/info.json"))
    fill = {
        "ids": SAMPLES["agent"]["Id"],
        "agent_id": AID,
        "session_id": SESSION_UUID,
        "process_id": f"pid:{AID}:4242",
        "aid": AID,
        "sensor_id": AID,
        "username": "alice",
    }
    overrides = {"get_ai_agent": {"agent_id": SAMPLES["agent"]["Id"]}}
    tested = 0
    for op in info["operations"]:
        params = {p["name"]: fill.get(p["name"], "x") for p in op["parameters"] if p.get("required")}
        params.update(overrides.get(op["operation"], {}))
        handler = operations.get(op["operation"])
        assert handler is not None, op["operation"]
        result = handler(config, resolve_dropdowns(config, op["operation"], params))
        # the dropdown populator returns a plain list of strings, by design
        assert isinstance(result, (dict, list)), op["operation"]
        tested += 1
    assert tested == len(info["operations"])
