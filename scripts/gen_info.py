#!/usr/bin/env python3
"""Generate info.json (metadata + config form + operation parameters).

    python3 scripts/gen_info.py

info.json is committed; this script is its source. Edit here, re-run, commit
both. tests/test_info.py checks the result against operations.py.
"""

import json
import os

VERSION = "1.0.0"

CLOUDS = [
    {"title": "US-1 (api.crowdstrike.com)", "value": "https://api.crowdstrike.com"},
    {"title": "US-2 (api.us-2.crowdstrike.com)", "value": "https://api.us-2.crowdstrike.com"},
    {"title": "EU-1 (api.eu-1.crowdstrike.com)", "value": "https://api.eu-1.crowdstrike.com"},
    {"title": "Custom (base URL below)", "value": "custom"},
]

ID_LIST = "One or more record ids, comma separated."


def P(
    name,
    title,
    description,
    type="text",
    required=False,
    value=None,
    options=None,
    placeholder=None,
    minimum=None,
    maximum=None,
    api=None,
    onchange=None,
):
    param = {
        "name": name,
        "title": title,
        "type": type,
        "editable": True,
        "visible": True,
        "required": required,
        "description": description,
        "tooltip": description,
    }
    if value is not None:
        param["value"] = value
    if options:
        param["options"] = options
    if placeholder:
        param["placeholder"] = placeholder
    if minimum is not None:
        param["minimum"] = minimum
    if maximum is not None:
        param["maximum"] = maximum
    if api:
        # Dynamic dropdown: the step editor fills it from this hidden operation.
        param["type"] = "select"
        param["apiOperation"] = api
    if onchange:
        # Pattern A conditional fields: value -> child fields.
        param["onchange"] = onchange
    return param


def PAGE(limit_default=50):
    return [
        P(
            "limit",
            "Limit",
            f"(Optional) Maximum number of records to return, 1-500. Defaults to {limit_default}.",
            "integer",
            value=limit_default,
            minimum=1,
            maximum=500,
        ),
        P(
            "offset",
            "Offset",
            "(Optional) Index of the first record to return, 0-1000, for paging. The API refuses an "
            "offset above 1000; narrow the time range instead of paging deeper.",
            "integer",
            value=0,
            minimum=0,
            maximum=1000,
        ),
    ]


def TIME(default, logscale=False):
    ceiling = (
        "LogScale-backed routes scan raw events and accept at most 7d."
        if logscale
        else "Entity-store routes serve up to 90d."
    )
    return P(
        "time_range",
        "Time Range",
        "(Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. "
        f"Defaults to {default}. {ceiling} "
        "If the API refuses the window, the connector retries narrower and reports it in notices.",
        value=default,
        placeholder="e.g. 7d",
    )


def PRODUCT(required=False):
    return P(
        "product",
        "AI Product",
        "(Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the "
        "dropdown or type a name; spaces and hyphens are normalized to underscores.",
        required=required,
        api="list_ai_product_options",
    )


def IDS(title="Ids", desc=ID_LIST):
    return P("ids", title, desc, required=True, placeholder="id1, id2")


SENSOR_ID = (
    "The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, "
    "so a host-scoped result covers every agent on that machine."
)


def OP(operation, title, description, parameters=None, schema=None, category="investigation"):
    return {
        "operation": operation,
        "title": title,
        "description": description,
        "category": category,
        "annotation": operation,
        "enabled": True,
        "visible": True,
        "parameters": parameters or [],
        "output_schema": schema or {},
    }


def LIST_SCHEMA():
    return {"records": [], "count": 0, "notices": []}


def RECORD_SCHEMA():
    return {"record": {}}


def IDS_SCHEMA():
    return {"records": [], "count": 0}


def POPULATOR(operation, title, description):
    op = OP(
        operation,
        title,
        description,
        schema={"type": "array", "items": {"type": "string"}},
        category="miscellaneous",
    )
    op["visible"] = False
    return op


SENSOR_PARAM = P(
    "agent_id", "Agent Id (sensor)", "(Optional) Filter by the 32-hex sensor id (aid), not the AIAgent.Id."
)

SESSION_PARAM = P("session_id", "Session Id", "(Optional) Filter by AgenticSessionId (UUID).")

AID_PARAM = P("aid", "Sensor Id (aid)", "(Optional) " + SENSOR_ID)

OPS = [
    # -- agents and inventory (AI entity store) ---------------------------
    OP(
        "list_ai_agents",
        "List AI Agents",
        "Lists AI agents from the Guardian AIAgent entity store, filtered by product or hostname and "
        "windowed by time_range on LastSeen. Records carry the opaque agent Id (pass it to Get AI Agent), "
        "the 32-hex SensorId (the host id that event queries filter on), the AgentIds content hashes, the "
        "product (a numeric tag id with a friendly AgentProductName sibling) and the seen timestamps.",
        [
            PRODUCT(),
            P("hostname", "Hostname", "(Optional) Filter by the hostname of the device running the agent."),
            TIME("7d"),
        ]
        + PAGE(),
        LIST_SCHEMA(),
    ),
    OP(
        "get_ai_agent",
        "Get AI Agent",
        "Gets one AI agent record by its opaque agent Id (the Id value from List AI Agents, not the "
        "32-hex SensorId and not an AgentIds content hash). The record carries SensorId, which the "
        "host-scoped follow-up actions (List AI Tool Usage, List AI Executions, List AI Detections) take.",
        [
            P(
                "agent_id",
                "Agent Id",
                "The AIAgent Id, the opaque record token from List AI Agents "
                "(for example ASCWQseSk3b76g...).",
                required=True,
            )
        ],
        RECORD_SCHEMA(),
    ),
    OP(
        "list_agent_sessions",
        "List AI Agent Sessions",
        "Lists AI agent sessions windowed by time_range on LastSeen, optionally by product. The route has "
        "no host filter: SensorId and AIAgentIds are never populated on this entity, so sessions cannot be "
        "scoped to one agent or host. Each record carries the session record Id, the AgenticSessionId "
        "UUID, the models invoked and the working directory.",
        [PRODUCT(), TIME("7d")] + PAGE(),
        LIST_SCHEMA(),
    ),
    OP(
        "get_agent_sessions",
        "Get AI Agent Sessions",
        "Gets AI agent session details by session record ids (the Id values from List AI Agent Sessions; "
        "these are AIAgentSession entity keys, not ThreatGraph vertices).",
        [IDS()],
        IDS_SCHEMA(),
    ),
    OP(
        "list_agent_installations",
        "List AI Agent Installations",
        "Lists AI agent installations (AIAgentInstallationView): agent name, product, version, install "
        "source, declaration and binary paths, binary SHA256, and the execution and inventory timestamps, "
        "optionally filtered by sensor id, product or hostname.",
        [
            P("sensor_id", "Sensor Id", "(Optional) " + SENSOR_ID),
            PRODUCT(),
            P("hostname", "Hostname", "(Optional) Filter by hostname."),
            TIME("7d"),
        ]
        + PAGE(),
        LIST_SCHEMA(),
    ),
    OP(
        "get_agent_installations",
        "Get AI Agent Installations",
        "Gets AI agent installation details by installation record ids (the Id values from List AI Agent "
        "Installations).",
        [IDS()],
        IDS_SCHEMA(),
    ),
    OP(
        "list_os_users",
        "List OS Users of AI Agents",
        "Lists OS users that ran AI agents (AIAgentOSUser), optionally filtered by sensor id, username or "
        "AD object SID.",
        [
            AID_PARAM,
            P("username", "Username", "(Optional) Filter by OS username."),
            P("object_sid", "Object SID", "(Optional) Filter by the Active Directory security identifier."),
            TIME("7d"),
        ]
        + PAGE(),
        LIST_SCHEMA(),
    ),
    OP(
        "get_os_user",
        "Get OS User of AI Agents",
        "Gets one OS user record by sensor id + username; the AIAgentOSUser entity is keyed on the pair.",
        [
            P("aid", "Sensor Id (aid)", SENSOR_ID, required=True),
            P("username", "Username", "The OS username.", required=True),
        ],
        RECORD_SCHEMA(),
    ),
    OP(
        "list_tools",
        "List AI Tools",
        "Lists the AI tool inventory (AITool): which tools exist and where they were seen. Rows are flat "
        "and host-scoped; the store covers few hosts, so for the invocations a host actually made prefer "
        "List AI Tool Usage.",
        [P("sensor_id", "Sensor Id", "(Optional) " + SENSOR_ID), TIME("7d")] + PAGE(),
        LIST_SCHEMA(),
    ),
    OP(
        "get_tools",
        "Get AI Tools",
        "Gets AI tool details by tool record ids (the Id values from List AI Tools).",
        [IDS()],
        IDS_SCHEMA(),
    ),
    OP(
        "list_skills",
        "List AI Skills",
        "Lists the fleet-wide inventory of AI skill frontmatters (AISkillFrontmatterView), optionally "
        "filtered by a name pattern.",
        [P("name_filter", "Name Filter", "(Optional) Substring filter on the skill name."), TIME("7d")]
        + PAGE(),
        LIST_SCHEMA(),
    ),
    OP(
        "get_skills",
        "Get AI Skills",
        "Gets AI skill frontmatter details by record ids (the Id values from List AI Skills).",
        [IDS()],
        IDS_SCHEMA(),
    ),
    OP(
        "list_mcp_server_names",
        "List MCP Server Names",
        "Lists MCP server names seen in the environment (MCPServerName). Fleet-wide: no agent or host "
        "filter, only time_range on LastSeen.",
        [TIME("7d")] + PAGE(),
        LIST_SCHEMA(),
    ),
    OP(
        "list_model_names",
        "List AI Model Names",
        "Lists AI model names (AIModelName) seen in the environment. Fleet-wide: the only server-side "
        "filter is time_range. For the model a specific session used, prefer List AI Agent Sessions "
        "(modelsInvoked) or List AI Executions (AgenticModel).",
        [TIME("7d")] + PAGE(),
        LIST_SCHEMA(),
    ),
    # -- LogScale-backed event queries ------------------------------------
    OP(
        "list_executions",
        "List AI Executions",
        "Lists AI agent process executions with the model and token counts for each (LogScale "
        "AgenticSessionStart; one row per process a session spawned). This is the only action that "
        "reports token usage (AgenticInputTokens / AgenticOutputTokens), and the only way to see the "
        "sessions on a given host: pass Sensor Id (aid), because the agent-sessions route has no host "
        "filter. Defaults to a 2-hour window like the API; widen Time Range for older activity (7d max).",
        [SESSION_PARAM, AID_PARAM, TIME("2h", logscale=True)] + PAGE(100),
        LIST_SCHEMA(),
    ),
    OP(
        "get_execution_detail",
        "Get AI Execution Detail",
        "Gets the execution detail for one AI session (AgenticSessionId UUID), optionally narrowed to one "
        "context process id.",
        [
            P("session_id", "Session Id", "The AgenticSessionId (UUID).", required=True),
            P(
                "context_process_id",
                "Context Process Id",
                "(Optional) Narrow the result to one context process id.",
            ),
        ],
        RECORD_SCHEMA(),
    ),
    OP(
        "list_tool_usage",
        "List AI Tool Usage",
        "Lists AI tool invocations (LogScale AgenticToolRequest): tool name, path, command line, query, "
        "skill and session, filterable by tool name, sensor id or session. Tool Name is exact and "
        'case-sensitive ("Bash", not "bash"); the event store and the tool catalog can differ in case. '
        "Defaults to a 2-hour window like the API; widen Time Range for older activity (7d max).",
        [
            P(
                "tool_name",
                "Tool Name",
                "(Optional) Filter by tool name. Exact and case-sensitive, "
                "for example Bash, Read, Edit, Grep.",
            ),
            AID_PARAM,
            SESSION_PARAM,
            TIME("2h", logscale=True),
        ]
        + PAGE(100),
        LIST_SCHEMA(),
    ),
    OP(
        "list_skill_usage",
        "List AI Skill Usage",
        "Lists per-invocation AI skill events (LogScale AgenticSkill rows), filterable by skill name, "
        "sensor id or session. Defaults to a 2-hour window like the API; widen Time Range for older "
        "activity (7d max).",
        [
            P("name", "Skill Name", "(Optional) Filter skill invocations by skill name (exact match)."),
            AID_PARAM,
            SESSION_PARAM,
            TIME("2h", logscale=True),
        ]
        + PAGE(100),
        LIST_SCHEMA(),
    ),
    OP(
        "list_prompts",
        "List AI Prompts",
        "Lists AI prompt records (LogScale AgenticUserPromptSubmit) within a session or host, including "
        "the prompt text and an epoch-millisecond timestamp. Defaults to a 2-hour window like the API; "
        "widen Time Range for older prompts (7d max).",
        [SESSION_PARAM, AID_PARAM, TIME("2h", logscale=True)] + PAGE(100),
        LIST_SCHEMA(),
    ),
    # -- agentic graph ------------------------------------------------------
    OP(
        "get_session_activity",
        "Get AI Session Activity",
        "Gets ThreatGraph activity for one or more AI sessions: the connected tools, models, processes, "
        "sub-agents and MCP servers. Accepts AgenticSessionId UUIDs or full vertex keys "
        "(aisess:{aid}:{uuid}); the server resolves either.",
        [
            IDS(
                "Session Ids",
                "One or more session ids (AgenticSessionId UUIDs or aisess:{aid}:{uuid} "
                "vertex keys), comma separated.",
            )
        ],
        IDS_SCHEMA(),
    ),
    OP(
        "get_process_tree",
        "Get AI Session Process Tree",
        "Gets the spawned process tree for an AI session, to a depth of 1-3 (default 2).",
        [
            P(
                "session_id",
                "Session Id",
                "The AgenticSessionId UUID or the aisess:{aid}:{uuid} vertex key.",
                required=True,
            ),
            P(
                "depth",
                "Depth",
                "(Optional) Process tree depth, 1-3. Defaults to 2.",
                "integer",
                value=2,
                minimum=1,
                maximum=3,
            ),
        ],
        IDS_SCHEMA(),
    ),
    OP(
        "get_network_events",
        "Get AI Session Network Events",
        "Gets outbound network connections from an AI session's processes.",
        [
            P(
                "session_id",
                "Session Id",
                "The AgenticSessionId UUID or the aisess:{aid}:{uuid} vertex key.",
                required=True,
            )
        ],
        IDS_SCHEMA(),
    ),
    OP(
        "get_file_events",
        "Get AI Session File Events",
        "Gets file write activity from an AI session's processes.",
        [
            P(
                "session_id",
                "Session Id",
                "The AgenticSessionId UUID or the aisess:{aid}:{uuid} vertex key.",
                required=True,
            )
        ],
        IDS_SCHEMA(),
    ),
    OP(
        "get_classified_file_access",
        "Get Classified File Access",
        "Gets FDP classified file access for one process. The process id has the form pid:{aid}:{upid}.",
        [
            P(
                "process_id",
                "Process Id",
                "The classified-file-access process id, pid:{aid}:{upid}.",
                required=True,
            )
        ],
        IDS_SCHEMA(),
    ),
    # -- detections ---------------------------------------------------------
    OP(
        "list_ai_detections",
        "List AI Detections",
        "Lists detections involving AI agent processes. The Agent Id parameter takes the 32-hex "
        "SENSOR/host id (AIAgent.SensorId, the aid), not the opaque AIAgent.Id; the API parameter name is "
        "misleading. Records carry Severity (0-100) and RiskScore (different metrics), the MITRE tactic "
        "and technique, the agentic product tag and a deep link into the Falcon console.",
        [SENSOR_PARAM, PRODUCT(), TIME("7d")] + PAGE(50),
        LIST_SCHEMA(),
    ),
    OP(
        "get_detection_scores",
        "Get AI Detection Scores",
        "Gets the Agentic Threat Score: the maximum detection severity per agent id and product. Joining "
        "a row onto an agent needs BOTH AgentId (the host sensor id) and AgenticProductTag, because a "
        "host usually runs several agents and most rows are unattributed. Capped at 500 groups, no "
        "pagination.",
        [SENSOR_PARAM, PRODUCT(), TIME("7d")],
        LIST_SCHEMA(),
    ),
    # -- aggregates ---------------------------------------------------------
    OP(
        "get_agent_product_counts",
        "Get Agent Counts by Product",
        "Gets agent counts grouped by product (aggregates/agents), for a fleet snapshot. Capped at 500 "
        "groups with no pagination; a full 500 means truncated.",
        [
            TIME("7d"),
            P(
                "limit",
                "Limit",
                "(Optional) Maximum number of groups to request, up to 500. Defaults to 500.",
                "integer",
                value=500,
                minimum=1,
                maximum=500,
            ),
        ],
        LIST_SCHEMA(),
        category="miscellaneous",
    ),
    OP(
        "get_session_product_counts",
        "Get Session Counts by Product",
        "Gets AI agent session counts grouped by product. Counts arrive as JSON strings from the API and "
        "are returned as numbers. Capped at 500 groups.",
        [PRODUCT(), TIME("7d")] + PAGE(500),
        LIST_SCHEMA(),
        category="miscellaneous",
    ),
    OP(
        "get_tool_name_counts",
        "Get Tool Counts by Name",
        "Gets AI tool counts grouped by tool name, optionally scoped to one host.",
        [
            P("sensor_id", "Sensor Id", "(Optional) " + SENSOR_ID),
            TIME("7d"),
            P(
                "limit",
                "Limit",
                "(Optional) Maximum number of groups to request, up to 500. Defaults to 500.",
                "integer",
                value=500,
                minimum=1,
                maximum=500,
            ),
        ],
        LIST_SCHEMA(),
        category="miscellaneous",
    ),
    OP(
        "get_skill_name_counts",
        "Get Skill Counts by Name",
        "Gets AI skill usage counts grouped by name, optionally filtered by a name pattern.",
        [P("name_filter", "Name Filter", "(Optional) Substring filter on the skill name."), TIME("7d")],
        LIST_SCHEMA(),
        category="miscellaneous",
    ),
    OP(
        "get_tool_usage_counts",
        "Get Tool Usage Counts",
        "Gets tool invocation counts by name from LogScale events, scoped by session or host. Defaults to "
        "a 2-hour window like the API; widen Time Range for older activity (7d max).",
        [SESSION_PARAM, AID_PARAM, TIME("2h", logscale=True)],
        LIST_SCHEMA(),
        category="miscellaneous",
    ),
    OP(
        "get_skill_usage_counts",
        "Get Skill Usage Counts",
        "Gets skill invocation counts by name from LogScale events, scoped by session or host. Defaults "
        "to a 2-hour window like the API; widen Time Range for older activity (7d max).",
        [SESSION_PARAM, AID_PARAM, TIME("2h", logscale=True)],
        LIST_SCHEMA(),
        category="miscellaneous",
    ),
    OP(
        "get_fleet_inventory",
        "Get Fleet Inventory",
        "Gets a fleet snapshot across five aggregates: AI agents and sessions by product, tools and "
        "skills by name, and a detection rollup with the worst Agentic Threat Score. Agents-by-product "
        "counts agents; sessions-by-product counts logical AIAgentSession rows, so do not relabel one as "
        "the other.",
        [
            TIME("7d"),
            PRODUCT(),
            P(
                "agent_id",
                "Agent Id (sensor)",
                "(Optional) Narrow the detection rollup to one host: the 32-hex sensor id (aid).",
            ),
        ],
        {
            "time_range": "",
            "agents_by_product": [],
            "sessions_by_product": [],
            "tools_by_name": [],
            "skills_by_name": [],
            "detections": {},
            "notices": [],
        },
        category="miscellaneous",
    ),
    # -- hidden dropdown populator -----------------------------------------
    POPULATOR(
        "list_ai_product_options",
        "List AI Product Options",
        "Returns the AI product names seen in the environment, for the AI Product dropdowns.",
    ),
    # -- ingestion ----------------------------------------------------------
    OP(
        "ingest_ai_detections",
        "Ingest AI Detections",
        "Fetches detections involving AI agent processes and maps them to FortiSOAR alerts. Called by the "
        "fetch playbook of the Data Ingestion wizard; time_range defaults to 24h.",
        [
            PRODUCT(),
            SENSOR_PARAM,
            TIME("24h"),
            P(
                "severity_min",
                "Minimum Severity",
                "(Optional) Only detections with Severity at or above this value (0-100). "
                "Defaults to 0 (all).",
                "integer",
                value=0,
                minimum=0,
                maximum=100,
            ),
            P(
                "max_records",
                "Maximum Records",
                "(Optional) Cap on alerts returned per run, 1-5000. Defaults to 200.",
                "integer",
                value=200,
                minimum=1,
                maximum=5000,
            ),
        ],
        {"alerts": [], "count": 0, "notices": []},
    ),
]

CONFIGURATION = {
    "fields": [
        P(
            "cloud",
            "CrowdStrike Cloud",
            "The CrowdStrike cloud your Falcon tenant runs on. Pick Custom to enter a base URL, for "
            "example for a government or allow-listed deployment.",
            "select",
            required=True,
            value=CLOUDS[0]["value"],
            options=CLOUDS,
            onchange={
                "custom": [
                    P(
                        "base_url",
                        "Base URL",
                        "Base URL of the CrowdStrike API for a custom cloud, for example "
                        "https://api.crowdstrike.com. Include the scheme; no trailing slash needed.",
                        required=True,
                        placeholder="https://api.crowdstrike.com",
                    ),
                ],
            },
        ),
        P(
            "client_id",
            "Client ID",
            "Client ID of the Falcon API client. Create it in the Falcon console under Support and "
            "resources > API clients and keys, with the AIDR: READ scope.",
            required=True,
            placeholder="API client id",
        ),
        P(
            "client_secret",
            "Client Secret",
            "Client Secret of the Falcon API client. Stored encrypted.",
            "password",
            required=True,
        ),
        P(
            "timeout",
            "Timeout",
            "(Optional) Request timeout in seconds. Defaults to 30.",
            "integer",
            value=30,
            minimum=1,
            maximum=300,
        ),
        P(
            "verify_ssl",
            "Verify SSL",
            "Whether the SSL certificate of the CrowdStrike API is to be validated. Defaults to true.",
            "checkbox",
            value=True,
        ),
    ]
}


def build():
    return {
        "name": "crowdstrike_guardian",
        "label": "CrowdStrike Falcon Guardian",
        "description": "CrowdStrike Falcon Guardian is CrowdStrike's AI detection and response (AIDR) "
        "solution. This connector queries the AI agent inventory (agents, sessions, "
        "installations, tools, skills, MCP servers, models), per-invocation activity "
        "(executions with model and token counts, tool and skill usage, prompts), the "
        "agentic graph (process tree, network and file events), and detections involving "
        "AI agent processes, and ingests those detections as FortiSOAR alerts on a "
        "schedule. Requires a Falcon API client with the AIDR: READ scope.",
        "publisher": "Community",
        "cs_approved": False,
        "cs_compatible": True,
        "version": VERSION,
        "category": "Threat Intelligence",
        "icon_small_name": "small_icon.png",
        "icon_large_name": "large_icon.png",
        "vendor_version": "Guardian AIDR API v1",
        "help_online": "https://developer.crowdstrike.com/api-reference/collections/aidr/",
        "ingestion_supported": True,
        "ingestion_modes": ["scheduled"],
        "ingestion_preferences": {"modules": ["alerts"]},
        "tags": ["CrowdStrike", "AI Security", "AIDR", "Guardian"],
        "configuration": CONFIGURATION,
        "operations": OPS,
    }


def main():
    info = build()
    here = os.path.dirname(os.path.abspath(__file__))
    target = os.path.join(here, "..", "crowdstrike_guardian", "info.json")
    with open(target, "w") as handle:
        json.dump(info, handle, indent=2, sort_keys=False)
        handle.write("\n")
    print(f"wrote {os.path.normpath(target)} ({len(info['operations'])} operations)")


if __name__ == "__main__":
    main()
