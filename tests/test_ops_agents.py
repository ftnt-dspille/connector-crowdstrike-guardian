"""Agent, session, installation and OS-user operations (the entity store)."""

import pytest
from conftest import AGENT_ID, AID, SAMPLES
from connectors.core.connector import ConnectorError


@pytest.mark.op("list_ai_agents")
def test_list_ai_agents_returns_records(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_agents

    result = list_ai_agents(config, {})
    assert result["count"] == 2
    agent = result["records"][0]
    assert agent["Id"] == AGENT_ID
    assert agent["SensorId"] == AID
    assert agent["AgentProductName"] == "Claude Code"
    assert result["pagination"]["limit"] == 50


@pytest.mark.op("list_ai_agents")
def test_list_ai_agents_filters_by_product(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_agents

    result = list_ai_agents(config, {"product": "claude code"})  # human spelling
    assert [r["AgentName"] for r in result["records"]] == ["claude-code"]
    sent = mock_api.calls_to("/aidr/queries/agents/v1")[0].params
    assert sent["product"] == "CLAUDE_CODE"  # normalized for the API


@pytest.mark.op("list_ai_agents")
def test_list_ai_agents_passes_hostname_and_paging(mock_api, config):
    from crowdstrike_guardian.operations import list_ai_agents

    list_ai_agents(config, {"hostname": "workstation-01", "limit": 1, "offset": 1})
    sent = mock_api.calls_to("/aidr/queries/agents/v1")[-1].params
    assert sent["hostname"] == "workstation-01"
    assert sent["limit"] == 1 and sent["offset"] == 1


@pytest.mark.op("get_ai_agent")
def test_get_ai_agent_by_record_token(mock_api, config):
    from crowdstrike_guardian.operations import get_ai_agent

    result = get_ai_agent(config, {"agent_id": AGENT_ID})
    assert result["record"]["Id"] == AGENT_ID
    assert result["record"]["AgentProductName"] == "Claude Code"


@pytest.mark.op("get_ai_agent")
def test_get_ai_agent_unknown_id_raises(mock_api, config):
    from crowdstrike_guardian.operations import get_ai_agent

    with pytest.raises(ConnectorError) as excinfo:
        get_ai_agent(config, {"agent_id": "no-such-agent"})
    assert "No AI agent found" in str(excinfo.value)


@pytest.mark.op("list_agent_sessions")
def test_list_agent_sessions_surfaces_the_nested_cim(mock_api, config):
    from crowdstrike_guardian.operations import list_agent_sessions

    result = list_agent_sessions(config, {})
    record = result["records"][0]
    assert record["Id"] == SAMPLES["session"]["Id"]
    assert record["session_id"] == "eb5ca156-1128-44ab-b933-3154a36e8a54"
    assert "claude-sonnet-4-5" in record["models_invoked"]
    assert record["working_directory"] == "/home/alice/project"


@pytest.mark.op("list_agent_sessions")
def test_list_agent_sessions_product_filter(mock_api, config):
    from crowdstrike_guardian.operations import list_agent_sessions

    list_agent_sessions(config, {"product": "Cursor"})
    sent = mock_api.calls_to("/aidr/queries/agent-sessions/v1")[0].params
    assert sent["product"] == "CURSOR"


@pytest.mark.op("get_agent_sessions")
def test_get_agent_sessions_by_ids(mock_api, config):
    from crowdstrike_guardian.operations import get_agent_sessions

    result = get_agent_sessions(config, {"ids": SAMPLES["session"]["Id"]})
    assert result["count"] == 1
    assert result["records"][0]["session_id"]


@pytest.mark.op("get_agent_sessions")
def test_get_agent_sessions_comma_separated_ids(mock_api, config):
    from crowdstrike_guardian.operations import get_agent_sessions

    result = get_agent_sessions(config, {"ids": "one, two"})
    assert mock_api.calls_to("/aidr/entities/agent-sessions/v1")[0].params["ids"] == ["one", "two"]
    assert result["count"] == 0  # fake has only one session record


@pytest.mark.op("list_agent_installations")
def test_list_agent_installations(mock_api, config):
    from crowdstrike_guardian.operations import list_agent_installations

    result = list_agent_installations(config, {"sensor_id": AID})
    record = result["records"][0]
    assert record["AgentVersion"] == "1.0.44"
    assert record["BinaryPath"] == "/usr/local/bin/claude"
    sent = mock_api.calls_to("/aidr/queries/agent-installations/v1")[0].params
    assert sent["sensor_id"] == AID


@pytest.mark.op("list_agent_installations")
def test_list_agent_installations_product_filter(mock_api, config):
    from crowdstrike_guardian.operations import list_agent_installations

    list_agent_installations(config, {"product": "CLAUDE_CODE"})
    sent = mock_api.calls_to("/aidr/queries/agent-installations/v1")[0].params
    assert sent["product"] == "CLAUDE_CODE"


@pytest.mark.op("get_agent_installations")
def test_get_agent_installations(mock_api, config):
    from crowdstrike_guardian.operations import get_agent_installations

    result = get_agent_installations(config, {"ids": SAMPLES["installation"]["Id"]})
    assert result["count"] == 1


@pytest.mark.op("get_agent_installations")
def test_get_agent_installations_unknown_id(mock_api, config):
    from crowdstrike_guardian.operations import get_agent_installations

    result = get_agent_installations(config, {"ids": "nope"})
    assert result["count"] == 0


@pytest.mark.op("list_os_users")
def test_list_os_users(mock_api, config):
    from crowdstrike_guardian.operations import list_os_users

    result = list_os_users(config, {"aid": AID})
    assert result["records"][0]["Username"] == "alice"


@pytest.mark.op("list_os_users")
def test_list_os_users_passes_object_sid(mock_api, config):
    from crowdstrike_guardian.operations import list_os_users

    list_os_users(config, {"object_sid": "S-1-5-21"})
    sent = mock_api.calls_to("/aidr/queries/agent-os-users/v1")[0].params
    assert sent["object_sid"] == "S-1-5-21"


@pytest.mark.op("get_os_user")
def test_get_os_user_keyed_on_aid_and_username(mock_api, config):
    from crowdstrike_guardian.operations import get_os_user

    result = get_os_user(config, {"aid": AID, "username": "alice"})
    assert result["record"]["ObjectSid"].startswith("S-1-5-21")


@pytest.mark.op("get_os_user")
def test_get_os_user_unknown_pair_raises(mock_api, config):
    from crowdstrike_guardian.operations import get_os_user

    with pytest.raises(ConnectorError):
        get_os_user(config, {"aid": AID, "username": "nobody"})
