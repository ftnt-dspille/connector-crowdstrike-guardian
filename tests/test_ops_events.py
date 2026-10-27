"""Tools, skills, MCP servers, models, and the LogScale-backed event queries."""

import pytest
from conftest import AID, SAMPLES, SESSION_UUID
from connectors.core.connector import ConnectorError


@pytest.mark.op("list_tools")
def test_list_tools(mock_api, config):
    from crowdstrike_guardian.operations import list_tools

    result = list_tools(config, {"sensor_id": AID})
    assert result["records"][0]["Name"] == "Bash"
    sent = mock_api.calls_to("/aidr/queries/tools/v1")[0].params
    assert sent["sensor_id"] == AID


@pytest.mark.op("list_tools")
def test_list_tools_without_filters(mock_api, config):
    from crowdstrike_guardian.operations import list_tools

    result = list_tools(config, {})
    assert result["count"] == 1
    sent = mock_api.calls_to("/aidr/queries/tools/v1")[0].params
    assert "sensor_id" not in sent  # blanks are dropped, not sent as empty


@pytest.mark.op("get_tools")
def test_get_tools(mock_api, config):
    from crowdstrike_guardian.operations import get_tools

    result = get_tools(config, {"ids": SAMPLES["tool"]["Id"]})
    assert result["records"][0]["Name"] == "Bash"


@pytest.mark.op("get_tools")
def test_get_tools_unknown_id_is_an_empty_result(mock_api, config):
    from crowdstrike_guardian.operations import get_tools

    assert get_tools(config, {"ids": "nope"})["count"] == 0


@pytest.mark.op("list_tool_usage")
def test_list_tool_usage_defaults_to_the_api_window(mock_api, config):
    from crowdstrike_guardian.operations import list_tool_usage

    result = list_tool_usage(config, {"aid": AID})
    assert result["count"] == 2
    sent = mock_api.calls_to("/aidr/queries/tool-usage/v1")[0].params
    assert sent["time_range"] == "2h"  # LogScale default, passed explicitly
    assert sent["aid"] == AID


@pytest.mark.op("list_tool_usage")
def test_list_tool_usage_tool_name_is_exact(mock_api, config):
    from crowdstrike_guardian.operations import list_tool_usage

    result = list_tool_usage(config, {"tool_name": "Bash"})
    assert [r["AgenticToolName"] for r in result["records"]] == ["Bash"]
    assert result["records"][0]["CommandLine"] == "pytest tests/test_ops.py -q"


@pytest.mark.op("list_tool_usage")
def test_list_tool_usage_case_mismatch_returns_zero_rows(mock_api, config):
    from crowdstrike_guardian.operations import list_tool_usage

    # 'bash' (lowercase) is a different tool name to the event store; the
    # result is empty rather than an error.
    result = list_tool_usage(config, {"tool_name": "bash"})
    assert result["count"] == 0


@pytest.mark.op("list_tool_usage")
def test_list_tool_usage_session_scope(mock_api, config):
    from crowdstrike_guardian.operations import list_tool_usage

    result = list_tool_usage(config, {"session_id": SESSION_UUID})
    assert result["count"] == 2
    sent = mock_api.calls_to("/aidr/queries/tool-usage/v1")[0].params
    assert sent["session_id"] == SESSION_UUID


@pytest.mark.op("list_skills")
def test_list_skills_and_name_filter(mock_api, config):
    from crowdstrike_guardian.operations import list_skills

    assert list_skills(config, {})["count"] == 1
    assert list_skills(config, {"name_filter": "review"})["count"] == 1
    assert list_skills(config, {"name_filter": "no-such-skill"})["count"] == 0


@pytest.mark.op("list_skills")
def test_list_skills_carries_description(mock_api, config):
    from crowdstrike_guardian.operations import list_skills

    record = list_skills(config, {})["records"][0]
    assert record["SkillName"] == "code-review"
    assert record["SkillDescription"]


@pytest.mark.op("get_skills")
def test_get_skills(mock_api, config):
    from crowdstrike_guardian.operations import get_skills

    result = get_skills(config, {"ids": SAMPLES["skill"]["Id"]})
    assert result["records"][0]["SkillName"] == "code-review"


@pytest.mark.op("get_skills")
def test_get_skills_unknown_id(mock_api, config):
    from crowdstrike_guardian.operations import get_skills

    assert get_skills(config, {"ids": "nope"})["count"] == 0


@pytest.mark.op("list_skill_usage")
def test_list_skill_usage(mock_api, config):
    from crowdstrike_guardian.operations import list_skill_usage

    result = list_skill_usage(config, {"name": "code-review", "aid": AID})
    assert result["records"][0]["AgenticSkill"] == "code-review"
    sent = mock_api.calls_to("/aidr/queries/skill-usage/v1")[0].params
    assert sent["time_range"] == "2h"


@pytest.mark.op("list_skill_usage")
def test_list_skill_usage_name_filter(mock_api, config):
    from crowdstrike_guardian.operations import list_skill_usage

    assert list_skill_usage(config, {"name": "other-skill"})["count"] == 0


@pytest.mark.op("list_mcp_server_names")
def test_list_mcp_server_names(mock_api, config):
    from crowdstrike_guardian.operations import list_mcp_server_names

    result = list_mcp_server_names(config, {})
    record = result["records"][0]
    assert record["server_name"] == "github-mcp"
    assert record["Cim"]["MCPServerName"]["serverName"] == "github-mcp"


@pytest.mark.op("list_mcp_server_names")
def test_list_mcp_server_names_passes_window(mock_api, config):
    from crowdstrike_guardian.operations import list_mcp_server_names

    list_mcp_server_names(config, {"time_range": "90d"})
    sent = mock_api.calls_to("/aidr/queries/mcp-server-names/v1")[0].params
    assert sent["time_range"] == "90d"


@pytest.mark.op("list_model_names")
def test_list_model_names(mock_api, config):
    from crowdstrike_guardian.operations import list_model_names

    result = list_model_names(config, {})
    assert result["records"][0]["model_name"] == "claude-sonnet-4-5"


@pytest.mark.op("list_model_names")
def test_list_model_names_no_scalar_filters(mock_api, config):
    from crowdstrike_guardian.operations import list_model_names

    list_model_names(config, {})
    sent = mock_api.calls_to("/aidr/queries/model-names/v1")[0].params
    assert set(sent) == {"time_range", "limit", "offset"}


@pytest.mark.op("list_executions")
def test_list_executions_reports_tokens(mock_api, config):
    from crowdstrike_guardian.operations import list_executions

    result = list_executions(config, {"aid": AID})
    tokens = {
        r["AgenticModel"]: (r["AgenticInputTokens"], r["AgenticOutputTokens"]) for r in result["records"]
    }
    assert tokens["claude-sonnet-4-5"] == (12345, 678)
    assert tokens["claude-haiku-4-5"] == (2048, 96)  # arrived as strings


@pytest.mark.op("list_executions")
def test_list_executions_session_scope(mock_api, config):
    from crowdstrike_guardian.operations import list_executions

    result = list_executions(config, {"session_id": SESSION_UUID})
    assert all(r["AgenticSessionId"] == SESSION_UUID for r in result["records"])


@pytest.mark.op("get_execution_detail")
def test_get_execution_detail(mock_api, config):
    from crowdstrike_guardian.operations import get_execution_detail

    result = get_execution_detail(config, {"session_id": SESSION_UUID})
    assert result["record"]["AgenticModel"] == "claude-sonnet-4-5"


@pytest.mark.op("get_execution_detail")
def test_get_execution_detail_unknown_session_raises(mock_api, config):
    from crowdstrike_guardian.operations import get_execution_detail

    with pytest.raises(ConnectorError):
        get_execution_detail(config, {"session_id": "00000000-0000-0000-0000-000000000000"})


@pytest.mark.op("list_prompts")
def test_list_prompts_coerce_timestamp(mock_api, config):
    from crowdstrike_guardian.operations import list_prompts

    result = list_prompts(config, {"session_id": SESSION_UUID})
    record = result["records"][0]
    assert record["timestamp"] == 1769551100000  # the API sent a string
    assert "Fix the failing import" in record["AgenticPrompt"]


@pytest.mark.op("list_prompts")
def test_list_prompts_host_scope(mock_api, config):
    from crowdstrike_guardian.operations import list_prompts

    list_prompts(config, {"aid": AID})
    sent = mock_api.calls_to("/aidr/queries/prompts/v1")[0].params
    assert sent["aid"] == AID


@pytest.mark.op("list_prompts")
def test_invalid_time_range_is_rejected_locally(mock_api, config):
    from crowdstrike_guardian.operations import list_prompts

    with pytest.raises(ConnectorError) as excinfo:
        list_prompts(config, {"time_range": "last week"})
    assert "Time range" in str(excinfo.value)
    assert not mock_api.calls_to("/aidr/queries/prompts/v1")
