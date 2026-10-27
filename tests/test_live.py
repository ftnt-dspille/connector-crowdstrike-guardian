"""
Online tests: every action against a real CrowdStrike Falcon tenant.

    cp tests/.env.example tests/.env    # fill in the API client, then:
    python3 -m pytest tests/test_live.py -m live -rs

The client needs the AIDR: READ scope. Everything here is read-only: nothing
is created, modified or deleted on the tenant. Tests that have no data to
work with (for example no AI agents have run recently) skip with the reason
instead of passing silently.

Each test names the action it proves with a live_op marker (see below);
tests/test_coverage.py fails if an action has no online test.
"""

import os
from pathlib import Path

import pytest

from crowdstrike_guardian.connector import CrowdStrikeGuardian
from crowdstrike_guardian.operations import operations

pytestmark = pytest.mark.live

_ENV_FILE = Path(__file__).resolve().parent / ".env"


def _load_env_file(path):
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
    except OSError:
        pass


if not os.environ.get("CS_CLIENT_ID") and _ENV_FILE.exists():
    _load_env_file(_ENV_FILE)


def _config():
    client_id = os.environ.get("CS_CLIENT_ID")
    client_secret = os.environ.get("CS_CLIENT_SECRET")
    if not client_id or not client_secret:
        pytest.skip("CS_CLIENT_ID / CS_CLIENT_SECRET not set -- live tests need a Falcon API client")
    config = {
        "client_id": client_id,
        "client_secret": client_secret,
        "cloud": os.environ.get("CS_CLOUD", "https://api.crowdstrike.com"),
        "verify_ssl": os.environ.get("CS_VERIFY_SSL", "true").lower() in ("true", "1", "yes"),
        "timeout": int(os.environ.get("CS_TIMEOUT", "60")),
    }
    if os.environ.get("CS_BASE_URL"):
        config["base_url"] = os.environ["CS_BASE_URL"]
    return config


@pytest.fixture(scope="module")
def config():
    return _config()


@pytest.fixture(scope="module")
def api(config):
    def call(name, params=None):
        return operations[name](config, params or {})

    return call


def live_op(name):
    """Mark a test as the online proof for one action."""
    return pytest.mark.live_op(name)


def _skip_if_empty(result, what):
    if not result.get("records"):
        pytest.skip(f"no {what} in this tenant for the requested window")
    return result


def _first_agent(api):
    return _skip_if_empty(api("list_ai_agents", {"time_range": "90d"}), "AI agents")["records"][0]


def _first_session(api):
    return _skip_if_empty(api("list_agent_sessions", {"time_range": "90d"}), "AI agent sessions")["records"][
        0
    ]


# -- health -----------------------------------------------------------------


def test_health_check(config):
    assert CrowdStrikeGuardian().check_health(config) is True


def test_bad_credentials_fail_clearly():
    config = _config()
    config["client_secret"] = "not-a-real-secret"
    from connectors.core.connector import ConnectorError

    with pytest.raises(ConnectorError) as err:
        CrowdStrikeGuardian().check_health(config)
    assert "401" in str(err.value) or "403" in str(err.value), str(err.value)


# -- entity store ------------------------------------------------------------


@live_op("list_ai_agents")
def test_list_ai_agents(api):
    result = api("list_ai_agents", {"time_range": "90d", "limit": 10})
    assert result["count"] >= 1
    record = result["records"][0]
    assert record["Id"] and record["SensorId"]


@live_op("get_ai_agent")
def test_get_ai_agent(api):
    agent = _first_agent(api)
    result = api("get_ai_agent", {"agent_id": agent["Id"]})
    assert result["record"]["Id"] == agent["Id"]


@live_op("list_agent_sessions")
def test_list_agent_sessions(api):
    result = api("list_agent_sessions", {"time_range": "90d", "limit": 10})
    assert result["count"] >= 1


@live_op("get_agent_sessions")
def test_get_agent_sessions(api):
    session = _first_session(api)
    result = api("get_agent_sessions", {"ids": session["Id"]})
    assert result["count"] == 1


@live_op("list_agent_installations")
def test_list_agent_installations(api):
    _skip_if_empty(api("list_agent_installations", {"time_range": "90d"}), "AI agent installations")


@live_op("get_agent_installations")
def test_get_agent_installations(api):
    install = _skip_if_empty(
        api("list_agent_installations", {"time_range": "90d"}), "AI agent installations"
    )["records"][0]
    result = api("get_agent_installations", {"ids": install["Id"]})
    assert result["count"] == 1


@live_op("list_os_users")
def test_list_os_users(api):
    _skip_if_empty(api("list_os_users", {"time_range": "90d"}), "OS users of AI agents")


@live_op("get_os_user")
def test_get_os_user(api):
    user = _skip_if_empty(api("list_os_users", {"time_range": "90d"}), "OS users of AI agents")["records"][0]
    result = api("get_os_user", {"aid": user["Aid"], "username": user["Username"]})
    assert result["record"]["Username"] == user["Username"]


@live_op("list_tools")
def test_list_tools(api):
    _skip_if_empty(api("list_tools", {"time_range": "90d"}), "AI tools")


@live_op("get_tools")
def test_get_tools(api):
    tool = _skip_if_empty(api("list_tools", {"time_range": "90d"}), "AI tools")["records"][0]
    result = api("get_tools", {"ids": tool["Id"]})
    assert result["count"] == 1


@live_op("list_skills")
def test_list_skills(api):
    _skip_if_empty(api("list_skills", {"time_range": "90d"}), "AI skills")


@live_op("get_skills")
def test_get_skills(api):
    skill = _skip_if_empty(api("list_skills", {"time_range": "90d"}), "AI skills")["records"][0]
    result = api("get_skills", {"ids": skill["Id"]})
    assert result["count"] == 1


@live_op("list_mcp_server_names")
def test_list_mcp_server_names(api):
    _skip_if_empty(api("list_mcp_server_names", {"time_range": "90d"}), "MCP server names")


@live_op("list_model_names")
def test_list_model_names(api):
    _skip_if_empty(api("list_model_names", {"time_range": "90d"}), "AI model names")


# -- LogScale event queries ---------------------------------------------------


@live_op("list_executions")
def test_list_executions(api):
    _skip_if_empty(api("list_executions", {"time_range": "7d"}), "AI executions")


@live_op("get_execution_detail")
def test_get_execution_detail(api):
    execution = _skip_if_empty(api("list_executions", {"time_range": "7d"}), "AI executions")["records"][0]
    result = api("get_execution_detail", {"session_id": execution["AgenticSessionId"]})
    assert result["record"]["AgenticSessionId"] == execution["AgenticSessionId"]


@live_op("list_tool_usage")
def test_list_tool_usage(api):
    _skip_if_empty(api("list_tool_usage", {"time_range": "7d"}), "AI tool usage")


@live_op("list_skill_usage")
def test_list_skill_usage(api):
    _skip_if_empty(api("list_skill_usage", {"time_range": "7d"}), "AI skill usage")


@live_op("list_prompts")
def test_list_prompts(api):
    _skip_if_empty(api("list_prompts", {"time_range": "7d"}), "AI prompts")


# -- agentic graph -------------------------------------------------------------


@live_op("get_session_activity")
def test_get_session_activity(api):
    session = _first_session(api)
    api("get_session_activity", {"ids": session["session_id"] or session["Id"]})


@live_op("get_process_tree")
def test_get_process_tree(api):
    session = _first_session(api)
    api("get_process_tree", {"session_id": session["session_id"] or session["Id"]})


@live_op("get_network_events")
def test_get_network_events(api):
    session = _first_session(api)
    api("get_network_events", {"session_id": session["session_id"] or session["Id"]})


@live_op("get_file_events")
def test_get_file_events(api):
    session = _first_session(api)
    api("get_file_events", {"session_id": session["session_id"] or session["Id"]})


@live_op("get_classified_file_access")
def test_get_classified_file_access(api):
    execution = _skip_if_empty(api("list_executions", {"time_range": "7d"}), "AI executions")["records"][0]
    process_id = execution.get("ContextProcessId")
    if not process_id:
        pytest.skip("no execution carried a ContextProcessId")
    api("get_classified_file_access", {"process_id": process_id})


# -- detections ----------------------------------------------------------------


@live_op("list_ai_detections")
def test_list_ai_detections(api):
    _skip_if_empty(api("list_ai_detections", {"time_range": "90d"}), "AI detections")


@live_op("get_detection_scores")
def test_get_detection_scores(api):
    _skip_if_empty(api("get_detection_scores", {"time_range": "90d"}), "detection scores")


# -- aggregates and inventory ---------------------------------------------------


@live_op("get_agent_product_counts")
def test_get_agent_product_counts(api):
    result = api("get_agent_product_counts", {"time_range": "90d"})
    assert result["count"] >= 1


@live_op("get_session_product_counts")
def test_get_session_product_counts(api):
    result = api("get_session_product_counts", {"time_range": "90d"})
    assert result["count"] >= 1


@live_op("get_tool_name_counts")
def test_get_tool_name_counts(api):
    api("get_tool_name_counts", {"time_range": "90d"})


@live_op("get_skill_name_counts")
def test_get_skill_name_counts(api):
    api("get_skill_name_counts", {"time_range": "90d"})


@live_op("get_tool_usage_counts")
def test_get_tool_usage_counts(api):
    api("get_tool_usage_counts", {"time_range": "7d"})


@live_op("get_skill_usage_counts")
def test_get_skill_usage_counts(api):
    api("get_skill_usage_counts", {"time_range": "7d"})


@live_op("get_fleet_inventory")
def test_get_fleet_inventory(api):
    result = api("get_fleet_inventory", {"time_range": "7d"})
    assert "agents_by_product" in result and "notices" in result


# -- dropdown populator ---------------------------------------------------------


@live_op("list_ai_product_options")
def test_list_ai_product_options(api):
    options = api("list_ai_product_options")
    assert isinstance(options, list)


# -- ingestion -------------------------------------------------------------------


@live_op("ingest_ai_detections")
def test_ingest_ai_detections(api):
    result = api("ingest_ai_detections", {"time_range": "90d", "max_records": 5})
    for alert in result["alerts"]:
        assert alert["external_id"] and alert["name"]
        assert alert["severity"] in ("Minimal", "Low", "Medium", "High", "Critical")
