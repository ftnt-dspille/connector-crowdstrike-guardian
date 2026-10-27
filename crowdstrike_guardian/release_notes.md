# CrowdStrike Falcon Guardian connector -- release notes

#### 1.0.0

Initial release.

- Queries the Falcon Guardian (AIDR) AI entity store: agents, agent sessions,
  installations, OS users, tools, skills, MCP server names and model names.
- Queries per-invocation activity from the LogScale-backed routes: executions
  with model and token counts, tool usage, skill usage and prompts.
- Queries the agentic graph: session activity, process tree, network events,
  file events and classified file access.
- Lists detections involving AI agent processes, with severity, risk score,
  MITRE tactic/technique and a deep link into the Falcon console.
- Fleet rollups: agent/session counts by product, tool/skill counts by name,
  the Agentic Threat Score, and a combined fleet inventory.
- Scheduled ingestion of AI-agent detections as FortiSOAR alerts.
- Handles OAuth2 client-credential token lifecycle, 429/5xx retries, and the
  API's time-window refusals (retries narrower and reports it in `notices`).

Requires a Falcon API client with the **AIDR: READ** scope.
