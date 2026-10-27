"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

CONNECTOR_NAME = 'crowdstrike_guardian'
CONNECTOR_VERSION = '1.0.0'

# Every /aidr route the connector can call. Falcon Guardian (the AIDR product)
# is read-only: 13 queries, 10 entities and 7 aggregates, all GET. The dict is
# keyed by the Falcon operation id so tests can assert every operation only
# touches routes declared for it.
ENDPOINTS = {
    # -- AI entity store -------------------------------------------------
    'queryAgentsV1': '/aidr/queries/agents/v1',
    'entitiesAgentsV1': '/aidr/entities/agents/v1',
    'queryAgentSessionsV1': '/aidr/queries/agent-sessions/v1',
    'entitiesAgentSessionsV1': '/aidr/entities/agent-sessions/v1',
    'queryAgentInstallationsV1': '/aidr/queries/agent-installations/v1',
    'entitiesAgentInstallationsV1': '/aidr/entities/agent-installations/v1',
    'queryAgentOSUsersV1': '/aidr/queries/agent-os-users/v1',
    'entitiesAgentOSUsersV1': '/aidr/entities/agent-os-users/v1',
    'queryToolsV1': '/aidr/queries/tools/v1',
    'entitiesToolsV1': '/aidr/entities/tools/v1',
    'querySkillsV1': '/aidr/queries/skills/v1',
    'entitiesSkillsV1': '/aidr/entities/skills/v1',
    'queryMcpServerNamesV1': '/aidr/queries/mcp-server-names/v1',
    'queryModelNamesV1': '/aidr/queries/model-names/v1',
    # -- LogScale-backed event queries ------------------------------------
    'queryExecutionsV1': '/aidr/queries/executions/v1',
    'entitiesExecutionsV1': '/aidr/entities/executions/v1',
    'queryToolUsageV1': '/aidr/queries/tool-usage/v1',
    'querySkillUsageV1': '/aidr/queries/skill-usage/v1',
    'queryPromptsV1': '/aidr/queries/prompts/v1',
    # -- ThreatGraph (agentic graph) --------------------------------------
    'entitiesSessionActivityV1': '/aidr/entities/session-activity/v1',
    'entitiesProcessTreeV1': '/aidr/entities/process-tree/v1',
    'entitiesNetworkEventsV1': '/aidr/entities/network-events/v1',
    'entitiesFileEventsV1': '/aidr/entities/file-events/v1',
    'entitiesClassifiedFileAccessV1': '/aidr/entities/classified-file-access/v1',
    # -- Detections and aggregates ----------------------------------------
    'queryDetectionsV1': '/aidr/queries/detections/v1',
    'aggregateAgentsV1': '/aidr/aggregates/agents/v1',
    'aggregateAgentSessionsV1': '/aidr/aggregates/agent-sessions/v1',
    'aggregateToolsV1': '/aidr/aggregates/tools/v1',
    'aggregateSkillsV1': '/aidr/aggregates/skills/v1',
    'aggregateToolUsageV1': '/aidr/aggregates/tool-usage/v1',
    'aggregateSkillUsageV1': '/aidr/aggregates/skill-usage/v1',
    'aggregateDetectionsV1': '/aidr/aggregates/detections/v1',
}

# LogScale-backed routes scan raw event data: they default to a 2-hour window
# and refuse anything wider than 7 days. Entity/aggregate routes serve up to
# 90 days. Only the entities/* routes reject time_range outright.
LOGSCALE_ROUTES = frozenset(ENDPOINTS[key] for key in (
    'queryExecutionsV1', 'queryToolUsageV1', 'querySkillUsageV1', 'queryPromptsV1',
))
LOGSCALE_DEFAULT_WINDOW = '2h'

# Applied when the API refuses a window (504 timeout, or a 400 naming
# time_range): retry progressively narrower and report it in `notices`.
WINDOW_LADDER = ('7d', '24h', '6h', '1h')

# Falcon clouds. us-gov-1 needs a separate contract; it is listed so the
# dropdown stays honest, but the API paths are identical across clouds.
CLOUDS = [
    {'title': 'US-1 (api.crowdstrike.com)', 'value': 'https://api.crowdstrike.com'},
    {'title': 'US-2 (api.us-2.crowdstrike.com)', 'value': 'https://api.us-2.crowdstrike.com'},
    {'title': 'EU-1 (api.eu-1.crowdstrike.com)', 'value': 'https://api.eu-1.crowdstrike.com'},
    {'title': 'Custom (base URL below)', 'value': 'custom'},
]
DEFAULT_CLOUD = 'https://api.crowdstrike.com'

TOKEN_PATH = '/oauth2/token'

# The token mint is a form post; the API answers 201 with expires_in seconds
# (CrowdStrike tokens live 30 minutes). Re-mint this many seconds early so a
# token that expires mid-flight does not fail the request it is attached to.
TOKEN_EXPIRY_SKEW_SECONDS = 60

# Health check does one cheap query; ingestion caps how far back it looks.
DEFAULT_TIMEOUT = 30
DEFAULT_LIMIT = 50
MAX_LIMIT = 500
MAX_OFFSET = 1000
MAX_PAGE_ROUNDS = 20
MAX_TOTAL_RECORDS = 5000

# Aggregates cap at 500 groups with no pagination; a full 500 means truncated.
AGGREGATE_GROUP_LIMIT = 500

MAX_ATTEMPTS = 3
MAX_RETRY_WAIT = 30

# Detections default lookback for the scheduled ingestion fetch.
INGESTION_DEFAULT_WINDOW = '24h'
INGESTION_MAX_WINDOW = '90d'
