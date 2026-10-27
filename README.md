# CrowdStrike Falcon Guardian connector for FortiSOAR

Query **CrowdStrike Falcon Guardian** (the AI Detection and Response, AIDR,
product) from FortiSOAR: the AI agent inventory, per-invocation agent activity,
the agentic graph, and detections involving AI agent processes - plus scheduled
ingestion of those detections as FortiSOAR alerts.

Auth is a Falcon API client (OAuth2 client credentials) with the **AIDR: READ**
scope. Every supported operation is a read: nothing is created, changed or
deleted on the tenant.

<!-- BEGIN GENERATED -->
### Configuration

| Field | Type | Required | Default | Description |
|---|---|---|---|---|
| `cloud` | select | yes | `https://api.crowdstrike.com` | The CrowdStrike cloud your Falcon tenant runs on. Pick Custom to enter a base URL, for example for a government or allow-listed deployment. |
| `client_id` | text | yes | - | Client ID of the Falcon API client. Create it in the Falcon console under Support and resources > API clients and keys, with the AIDR: READ scope. |
| `client_secret` | password | yes | - | Client Secret of the Falcon API client. Stored encrypted. |
| `timeout` | integer | no | `30` | (Optional) Request timeout in seconds. Defaults to 30. |
| `verify_ssl` | checkbox | no | `True` | Whether the SSL certificate of the CrowdStrike API is to be validated. Defaults to true. |

The Cloud field carries an onchange rule: picking *Custom (base URL below)* reveals a required **Base URL** field for deployments not covered by the dropdown.

### AI agent inventory (AI entity store)

#### `list_ai_agents`

Lists AI agents from the Guardian AIAgent entity store, filtered by product or hostname and windowed by time_range on LastSeen. Records carry the opaque agent Id (pass it to Get AI Agent), the 32-hex SensorId (the host id that event queries filter on), the AgentIds content hashes, the product (a numeric tag id with a friendly AgentProductName sibling) and the seen timestamps.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `hostname` | Hostname | text | no | (Optional) Filter by the hostname of the device running the agent. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_ai_agent`

Gets one AI agent record by its opaque agent Id (the Id value from List AI Agents, not the 32-hex SensorId and not an AgentIds content hash). The record carries SensorId, which the host-scoped follow-up actions (List AI Tool Usage, List AI Executions, List AI Detections) take.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `agent_id` | Agent Id | text | yes | The AIAgent Id, the opaque record token from List AI Agents (for example ASCWQseSk3b76g...). |

#### `list_agent_sessions`

Lists AI agent sessions windowed by time_range on LastSeen, optionally by product. The route has no host filter: SensorId and AIAgentIds are never populated on this entity, so sessions cannot be scoped to one agent or host. Each record carries the session record Id, the AgenticSessionId UUID, the models invoked and the working directory.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_agent_sessions`

Gets AI agent session details by session record ids (the Id values from List AI Agent Sessions; these are AIAgentSession entity keys, not ThreatGraph vertices).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `ids` | Ids | text | yes | One or more record ids, comma separated. |

#### `list_agent_installations`

Lists AI agent installations (AIAgentInstallationView): agent name, product, version, install source, declaration and binary paths, binary SHA256, and the execution and inventory timestamps, optionally filtered by sensor id, product or hostname.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `sensor_id` | Sensor Id | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `hostname` | Hostname | text | no | (Optional) Filter by hostname. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_agent_installations`

Gets AI agent installation details by installation record ids (the Id values from List AI Agent Installations).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `ids` | Ids | text | yes | One or more record ids, comma separated. |

#### `list_os_users`

Lists OS users that ran AI agents (AIAgentOSUser), optionally filtered by sensor id, username or AD object SID.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `aid` | Sensor Id (aid) | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `username` | Username | text | no | (Optional) Filter by OS username. |
| `object_sid` | Object SID | text | no | (Optional) Filter by the Active Directory security identifier. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_os_user`

Gets one OS user record by sensor id + username; the AIAgentOSUser entity is keyed on the pair.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `aid` | Sensor Id (aid) | text | yes | The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `username` | Username | text | yes | The OS username. |

#### `list_tools`

Lists the AI tool inventory (AITool): which tools exist and where they were seen. Rows are flat and host-scoped; the store covers few hosts, so for the invocations a host actually made prefer List AI Tool Usage.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `sensor_id` | Sensor Id | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_tools`

Gets AI tool details by tool record ids (the Id values from List AI Tools).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `ids` | Ids | text | yes | One or more record ids, comma separated. |

#### `list_skills`

Lists the fleet-wide inventory of AI skill frontmatters (AISkillFrontmatterView), optionally filtered by a name pattern.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `name_filter` | Name Filter | text | no | (Optional) Substring filter on the skill name. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_skills`

Gets AI skill frontmatter details by record ids (the Id values from List AI Skills).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `ids` | Ids | text | yes | One or more record ids, comma separated. |

#### `list_mcp_server_names`

Lists MCP server names seen in the environment (MCPServerName). Fleet-wide: no agent or host filter, only time_range on LastSeen.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `list_model_names`

Lists AI model names (AIModelName) seen in the environment. Fleet-wide: the only server-side filter is time_range. For the model a specific session used, prefer List AI Agent Sessions (modelsInvoked) or List AI Executions (AgenticModel).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

### Per-invocation activity (LogScale-backed)

#### `list_executions`

Lists AI agent process executions with the model and token counts for each (LogScale AgenticSessionStart; one row per process a session spawned). This is the only action that reports token usage (AgenticInputTokens / AgenticOutputTokens), and the only way to see the sessions on a given host: pass Sensor Id (aid), because the agent-sessions route has no host filter. Defaults to a 2-hour window like the API; widen Time Range for older activity (7d max).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | no | (Optional) Filter by AgenticSessionId (UUID). |
| `aid` | Sensor Id (aid) | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 2h. LogScale-backed routes scan raw events and accept at most 7d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `2h`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 100. (default `100`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_execution_detail`

Gets the execution detail for one AI session (AgenticSessionId UUID), optionally narrowed to one context process id.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | yes | The AgenticSessionId (UUID). |
| `context_process_id` | Context Process Id | text | no | (Optional) Narrow the result to one context process id. |

#### `list_tool_usage`

Lists AI tool invocations (LogScale AgenticToolRequest): tool name, path, command line, query, skill and session, filterable by tool name, sensor id or session. Tool Name is exact and case-sensitive ("Bash", not "bash"); the event store and the tool catalog can differ in case. Defaults to a 2-hour window like the API; widen Time Range for older activity (7d max).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `tool_name` | Tool Name | text | no | (Optional) Filter by tool name. Exact and case-sensitive, for example Bash, Read, Edit, Grep. |
| `aid` | Sensor Id (aid) | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `session_id` | Session Id | text | no | (Optional) Filter by AgenticSessionId (UUID). |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 2h. LogScale-backed routes scan raw events and accept at most 7d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `2h`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 100. (default `100`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `list_skill_usage`

Lists per-invocation AI skill events (LogScale AgenticSkill rows), filterable by skill name, sensor id or session. Defaults to a 2-hour window like the API; widen Time Range for older activity (7d max).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `name` | Skill Name | text | no | (Optional) Filter skill invocations by skill name (exact match). |
| `aid` | Sensor Id (aid) | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `session_id` | Session Id | text | no | (Optional) Filter by AgenticSessionId (UUID). |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 2h. LogScale-backed routes scan raw events and accept at most 7d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `2h`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 100. (default `100`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `list_prompts`

Lists AI prompt records (LogScale AgenticUserPromptSubmit) within a session or host, including the prompt text and an epoch-millisecond timestamp. Defaults to a 2-hour window like the API; widen Time Range for older prompts (7d max).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | no | (Optional) Filter by AgenticSessionId (UUID). |
| `aid` | Sensor Id (aid) | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 2h. LogScale-backed routes scan raw events and accept at most 7d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `2h`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 100. (default `100`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

### Agentic graph (ThreatGraph)

#### `get_session_activity`

Gets ThreatGraph activity for one or more AI sessions: the connected tools, models, processes, sub-agents and MCP servers. Accepts AgenticSessionId UUIDs or full vertex keys (aisess:{aid}:{uuid}); the server resolves either.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `ids` | Session Ids | text | yes | One or more session ids (AgenticSessionId UUIDs or aisess:{aid}:{uuid} vertex keys), comma separated. |

#### `get_process_tree`

Gets the spawned process tree for an AI session, to a depth of 1-3 (default 2).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | yes | The AgenticSessionId UUID or the aisess:{aid}:{uuid} vertex key. |
| `depth` | Depth | integer | no | (Optional) Process tree depth, 1-3. Defaults to 2. (default `2`) |

#### `get_network_events`

Gets outbound network connections from an AI session's processes.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | yes | The AgenticSessionId UUID or the aisess:{aid}:{uuid} vertex key. |

#### `get_file_events`

Gets file write activity from an AI session's processes.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | yes | The AgenticSessionId UUID or the aisess:{aid}:{uuid} vertex key. |

#### `get_classified_file_access`

Gets FDP classified file access for one process. The process id has the form pid:{aid}:{upid}.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `process_id` | Process Id | text | yes | The classified-file-access process id, pid:{aid}:{upid}. |

### Detections

#### `list_ai_detections`

Lists detections involving AI agent processes. The Agent Id parameter takes the 32-hex SENSOR/host id (AIAgent.SensorId, the aid), not the opaque AIAgent.Id; the API parameter name is misleading. Records carry Severity (0-100) and RiskScore (different metrics), the MITRE tactic and technique, the agentic product tag and a deep link into the Falcon console.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `agent_id` | Agent Id (sensor) | text | no | (Optional) Filter by the 32-hex sensor id (aid), not the AIAgent.Id. |
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 50. (default `50`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_detection_scores`

Gets the Agentic Threat Score: the maximum detection severity per agent id and product. Joining a row onto an agent needs BOTH AgentId (the host sensor id) and AgenticProductTag, because a host usually runs several agents and most rows are unattributed. Capped at 500 groups, no pagination.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `agent_id` | Agent Id (sensor) | text | no | (Optional) Filter by the 32-hex sensor id (aid), not the AIAgent.Id. |
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |

### Fleet rollups (aggregates)

#### `get_agent_product_counts`

Gets agent counts grouped by product (aggregates/agents), for a fleet snapshot. Capped at 500 groups with no pagination; a full 500 means truncated.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of groups to request, up to 500. Defaults to 500. (default `500`) |

#### `get_session_product_counts`

Gets AI agent session counts grouped by product. Counts arrive as JSON strings from the API and are returned as numbers. Capped at 500 groups.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of records to return, 1-500. Defaults to 500. (default `500`) |
| `offset` | Offset | integer | no | (Optional) Index of the first record to return, 0-1000, for paging. The API refuses an offset above 1000; narrow the time range instead of paging deeper. (default `0`) |

#### `get_tool_name_counts`

Gets AI tool counts grouped by tool name, optionally scoped to one host.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `sensor_id` | Sensor Id | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `limit` | Limit | integer | no | (Optional) Maximum number of groups to request, up to 500. Defaults to 500. (default `500`) |

#### `get_skill_name_counts`

Gets AI skill usage counts grouped by name, optionally filtered by a name pattern.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `name_filter` | Name Filter | text | no | (Optional) Substring filter on the skill name. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |

#### `get_tool_usage_counts`

Gets tool invocation counts by name from LogScale events, scoped by session or host. Defaults to a 2-hour window like the API; widen Time Range for older activity (7d max).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | no | (Optional) Filter by AgenticSessionId (UUID). |
| `aid` | Sensor Id (aid) | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 2h. LogScale-backed routes scan raw events and accept at most 7d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `2h`) |

#### `get_skill_usage_counts`

Gets skill invocation counts by name from LogScale events, scoped by session or host. Defaults to a 2-hour window like the API; widen Time Range for older activity (7d max).

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `session_id` | Session Id | text | no | (Optional) Filter by AgenticSessionId (UUID). |
| `aid` | Sensor Id (aid) | text | no | (Optional) The 32-hex sensor id (aid) of the HOST. Many hosts run more than one AI agent, so a host-scoped result covers every agent on that machine. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 2h. LogScale-backed routes scan raw events and accept at most 7d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `2h`) |

#### `get_fleet_inventory`

Gets a fleet snapshot across five aggregates: AI agents and sessions by product, tools and skills by name, and a detection rollup with the worst Agentic Threat Score. Agents-by-product counts agents; sessions-by-product counts logical AIAgentSession rows, so do not relabel one as the other.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 7d. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `7d`) |
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `agent_id` | Agent Id (sensor) | text | no | (Optional) Narrow the detection rollup to one host: the 32-hex sensor id (aid). |

### Ingestion

#### `ingest_ai_detections`

Fetches detections involving AI agent processes and maps them to FortiSOAR alerts. Called by the fetch playbook of the Data Ingestion wizard; time_range defaults to 24h.

| Parameter | Title | Type | Required | Description |
|---|---|---|---|---|
| `product` | AI Product | select | no | (Optional) Filter by AI product name, for example CLAUDE_CODE or CURSOR. Pick from the dropdown or type a name; spaces and hyphens are normalized to underscores. (dropdown, filled by `list_ai_product_options`) |
| `agent_id` | Agent Id (sensor) | text | no | (Optional) Filter by the 32-hex sensor id (aid), not the AIAgent.Id. |
| `time_range` | Time Range | text | no | (Optional) Lookback window: a number with m, h or d, for example 2h, 24h or 7d. Defaults to 24h. Entity-store routes serve up to 90d. If the API refuses the window, the connector retries narrower and reports it in notices. (default `24h`) |
| `severity_min` | Minimum Severity | integer | no | (Optional) Only detections with Severity at or above this value (0-100). Defaults to 0 (all). (default `0`) |
| `max_records` | Maximum Records | integer | no | (Optional) Cap on alerts returned per run, 1-5000. Defaults to 200. (default `200`) |

### Output conventions

- List actions return `records` (the API records, original field names), `count`, `pagination` when the API paged, and `notices` when something had to be adjusted (a narrowed time range, a truncated aggregate).
- Get actions return `record`.
- Aggregates return rows of `label`/`count` (or `product`/`count`, `tool`/`count`, `skill`/`count`); counts arrive as JSON strings from the API and are returned as numbers.
- `get_fleet_inventory` returns `agents_by_product`, `sessions_by_product`, `tools_by_name`, `skills_by_name` and a `detections` rollup.
<!-- END GENERATED -->

## What the API actually behaves like

These are the rules the connector codes around; they are worth knowing before
writing playbooks against the output.

- **Three identifiers, do not conflate.**
  - `Id` on an agent record is an *opaque record token* - that is what
    `get_ai_agent` takes.
  - `SensorId` (the `aid`) is a **32-hex host id**. The event queries
    (`list_tool_usage`, `list_skill_usage`, `list_executions`, `list_prompts`)
    filter on it, and a host often runs several AI agents - host-scoped results
    cover all of them.
  - `AgentIds[]` is a content hash; no endpoint accepts it as a filter.
- **Two product encodings.** Entity sources answer with a numeric tag id
  (sometimes a string, sometimes an int) plus a friendly `<field>Name`
  sibling; the LogScale event sources answer with names. On *input* the API
  always wants the name (`CLAUDE_CODE`); the connector normalizes
  `Claude Code` / `claude-code` for you. `0` and `null` both mean
  *unattributed*.
- **Time windows.** Entity-store routes filter `LastSeen` and serve up to 90
  days. The LogScale-backed routes scan raw events, default to a **2 hour**
  window when `time_range` is omitted, and cap at **7 days**. If the API
  refuses a window (a 504, or a 400 naming `time_range`), the connector
  retries progressively narrower and says so in `notices`.
- **Aggregates cap at 500 groups** with no pagination; a full 500 means
  truncated. The connector flags that in `notices`.
- **`meta.pagination.total` only tells the truth on a short page** (it is
  synthesized as `offset + len(page)`). The connector pages by page length,
  not by total.
- **Errors follow the Falcon envelope.** 400 names the offending parameter;
  403 means the API client lacks `AIDR: READ` (or the Guardian API flag is off
  for the CID); 504 means the query was too broad, not that the API is broken.

## Data ingestion

The connector ships a fetch action, `ingest_ai_detections`, and the sample
playbooks for the Data Ingestion wizard (scheduled mode). Each run pulls
detections involving AI agent processes for the configured window, maps them to
FortiSOAR alerts (severity from Falcon's `SeverityName`, state from `Status`,
MITRE tactic/technique, Falcon console deep link), and creates or updates them
in the `alerts` module. Filters: product, agent (sensor) id, minimum severity,
and a per-run record cap.

The fetch is incremental: a dynamic variable stores the last successful pull
time, each run pulls the hours elapsed since then (rounded up; cold start uses
the wizard-configured lookback), and the watermark advances only after the
alerts are written. Alerts upsert on `sourceId`, so an overlapping window
updates records instead of duplicating them.

## Requirements

- FortiSOAR 7.6.0 or later (developed and tested against 8.0).
- A CrowdStrike Falcon API client with the **AIDR: READ** scope. Create it in
  the Falcon console under *Support and resources > API clients and keys*.
- Network reachability from the FortiSOAR cluster to the chosen cloud's API
  host (`api.crowdstrike.com`, `api.us-2.crowdstrike.com` or
  `api.eu-1.crowdstrike.com`, or your custom base URL).

## Development

```
python3 -m pytest tests -q          # offline suite, no network
python3 -m pytest tests -m live -rs # online suite (needs tests/.env)
ruff check tests scripts tools      # lint
python3 scripts/gen_info.py         # regenerate info.json after editing it
python3 scripts/gen_docs.py         # regenerate README tables
python3 tools/make_icon.py          # regenerate icons
python3 crowdstrike_guardian/playbooks/build.py   # recompile playbooks.json (needs fsrpb)
./scripts/package.sh                # build dist/<name>-<version>.tgz
```

The offline suite stubs the FortiSOAR SDK and answers every Falcon route from
fixtures (`tests/fixtures/guardian_samples.json`) through a stateful fake, so
the whole connector surface is exercised with no tenant. The online suite
proves the same operations against a real tenant and skips cleanly without
credentials; every operation must have both (tests/test_coverage.py enforces
it).

Layout:

| Path | What it is |
|---|---|
| `crowdstrike_guardian/` | The connector package (what ships in the .tgz) |
| `crowdstrike_guardian/client.py` | OAuth2 token lifecycle, retries, window ladder, pagination |
| `crowdstrike_guardian/models.py` | Pydantic models validating/coercing every response |
| `crowdstrike_guardian/operations.py` | The operation handlers and dispatch |
| `crowdstrike_guardian/field_mapping.py` | Detection -> FortiSOAR alert mapping |
| `crowdstrike_guardian/playbooks/` | Sample playbooks: `playbooks.yaml` source, `build.py` compiler driver, `playbooks.json` build output |
| `scripts/gen_info.py` | Source of truth for info.json |
| `scripts/gen_docs.py` | README generated sections |
| `tests/` | Offline + online suites |

## Release

CI runs the offline suite on every push and PR. Tagging `v<x.y.z>` builds the
bundle (the tag must match `info.json`'s version) and attaches the `.tgz` to a
GitHub release. Install in FortiSOAR via *Content Hub > Connectors > Add* and
upload the tarball.

## License

MIT - see [LICENSE](LICENSE).
