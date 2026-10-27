"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""
import re

from connectors.core.connector import ConnectorError, get_logger

from .client import GuardianClient
from .constants import (
    DEFAULT_LIMIT,
    ENDPOINTS as ROUTES,
    INGESTION_DEFAULT_WINDOW,
    LOGSCALE_DEFAULT_WINDOW,
    MAX_TOTAL_RECORDS,
)
from .field_mapping import map_detection_to_alert
from .models import (
    AgentRecord,
    AgentSessionRecord,
    AggregateBucket,
    DetectionRecord,
    ExecutionRecord,
    InstallationRecord,
    McpServerRecord,
    ModelNameRecord,
    OsUserRecord,
    PromptRecord,
    SkillRecord,
    SkillUsageRecord,
    ToolRecord,
    ToolUsageRecord,
    parse_envelope,
)

logger = get_logger('crowdstrike_guardian')

TIME_RANGE = re.compile(r'^\d+\s*(m|h|d)$', re.I)
# parameter helpers
# ---------------------------------------------------------------------------

def _blank(value):
    if isinstance(value, str):
        return not value.strip()
    return value is None or value == [] or value == {}


def _require(params, *names):
    for name in names:
        if _blank(params.get(name)):
            raise ConnectorError('Parameter "%s" is required.' % name)


def _text(value, name='value', allow_blank=False):
    value = '' if value is None else str(value).strip()
    if not value and not allow_blank:
        raise ConnectorError('Parameter "%s" is required.' % name)
    return value


def _int_param(value, name, default=None, minimum=1, maximum=500):
    if _blank(value):
        if default is None:
            raise ConnectorError('Parameter "%s" is required.' % name)
        return default
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ConnectorError('Parameter "%s" must be a whole number.' % name)
    if number < minimum or number > maximum:
        raise ConnectorError('Parameter "%s" must be between %s and %s.' % (name, minimum, maximum))
    return number


def _time_range(value, default):
    """Validate a Guardian time_range ('2h', '7d', '90d'). The API is the
    authority on ceilings (90d entity store, 7d LogScale events); the client
    narrows and reports if it refuses."""
    if _blank(value):
        return default
    text = str(value).strip()
    if not TIME_RANGE.match(text):
        raise ConnectorError('Time range "%s" is not valid. Use a number with m, h or d, '
                             'for example 2h, 24h or 7d.' % text)
    return text.replace(' ', '')


def _page(params, default_limit=DEFAULT_LIMIT):
    limit = _int_param(params.get('limit'), 'limit', default=default_limit)
    offset = _int_param(params.get('offset'), 'offset', default=0, minimum=0)
    return limit, offset


def _normalize_product(value):
    """'claude code', 'Claude-Code', 'CLAUDE_CODE' -> 'CLAUDE_CODE'.

    The API takes the product name on input; entity sources answer with a
    numeric tag id on output, decorated with a friendly <field>Name sibling.
    UPPER_SNAKE of the friendly name is what the input wants.
    """
    text = str(value or '').strip()
    if not text:
        return ''
    return re.sub(r'[\s\-]+', '_', text).upper()


def resolve_dropdowns(config, operation, params):
    """Map each picked dropdown title to the value the API needs.

    Product dropdowns carry friendly names ("Claude Code"); every product
    input wants the UPPER_SNAKE form, which is derivable from the display
    text, so the conversion needs no lookup.
    """
    out = dict(params or {})
    for name in _PRODUCT_PARAMS.get(operation, ()):
        text = out.get(name)
        if isinstance(text, str) and text.strip() and '{{' not in text:
            out[name] = _normalize_product(text)
        elif isinstance(text, list) and text:
            out[name] = [_normalize_product(v) for v in text]
    return out


# product-typed parameters per operation; resolve_dropdowns walks this table
_PRODUCT_PARAMS = {
    'list_ai_agents': ('product',),
    'list_agent_sessions': ('product',),
    'list_agent_installations': ('product',),
    'list_ai_detections': ('product',),
    'get_detection_scores': ('product',),
    'get_agent_product_counts': ('product',),
    'get_session_product_counts': ('product',),
    'get_fleet_inventory': ('product',),
}


def _dump(model, extras=None):
    """Validate-dump a record: original API keys, plus selected normalized
    fields so playbooks do not have to dig into nested Cim objects."""
    data = model.model_dump(by_alias=True, exclude_none=False)
    if extras:
        data.update(extras)
    return data


def _records(envelope, model, extras_of=None):
    """Validate an envelope of records into plain dicts ready for playbooks."""
    parsed = parse_envelope(envelope, model)
    records = [_dump(r, extras_of(r) if extras_of else None) for r in parsed.resources]
    return records, parsed


def _result(records, parsed, notices=None, **extra):
    out = {'records': records, 'count': len(records)}
    page = parsed.pagination
    if page:
        out['pagination'] = {'limit': page.limit, 'offset': page.offset, 'total': page.total}
    if parsed.errors:
        out['api_errors'] = parsed.error_messages
    if notices:
        out['notices'] = notices
    out.update(extra)
    return out


def _single(envelope, model, what, extras=None):
    parsed = parse_envelope(envelope, model)
    if parsed.errors:
        raise ConnectorError('Guardian returned an error: %s' % '; '.join(parsed.error_messages))
    if not parsed.resources:
        raise ConnectorError('No %s found for the given id.' % what)
    record = parsed.resources[0]
    return _dump(record, extras)


def _graph_result(envelope, notices=None, **extra):
    """Agentic-graph endpoints answer with vertex/edge payloads rather than
    typed records; validate the envelope and pass the resources through."""
    parsed = parse_envelope(envelope, None)
    out = {'records': parsed.resources, 'count': len(parsed.resources)}
    if parsed.errors:
        out['api_errors'] = parsed.error_messages
    if notices:
        out['notices'] = notices
    out.update(extra)
    return out


def _client(config):
    return GuardianClient(config)


# ---------------------------------------------------------------------------
# health
# ---------------------------------------------------------------------------

def check_health(config, **kwargs):
    """One cheap authenticated query proves token, cloud and AIDR: READ."""
    client = _client(config)
    envelope = client.request('GET', ROUTES['queryAgentsV1'], {'limit': 1})
    parsed = parse_envelope(envelope, AgentRecord)
    if parsed.errors:
        raise ConnectorError('Guardian reported an error: %s' % '; '.join(parsed.error_messages))
    logger.info('Guardian health check ok (%d agent resource(s) visible)', len(parsed.resources))
    return True


# ---------------------------------------------------------------------------
# agents and inventory (AI entity store)
# ---------------------------------------------------------------------------

def list_ai_agents(config, params):
    """List AI agents from the AIAgent entity store.

    `Id` is the opaque record token (get_ai_agent takes it); `SensorId` is the
    32-hex HOST id (aid) that the event queries filter on -- many hosts run
    more than one agent, so host-scoped results cover all of them.
    """
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryAgentsV1'],
        {'product': _normalize_product(params.get('product')),
         'hostname': params.get('hostname'),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, AgentRecord)
    return _result(records, parsed, notices)


def get_ai_agent(config, params):
    _require(params, 'agent_id')
    agent_id = _text(params.get('agent_id'), 'agent_id')
    record = _single(_client(config).request('GET', ROUTES['entitiesAgentsV1'],
                                             {'ids': agent_id}),
                     AgentRecord, 'AI agent')
    return {'record': record}


def list_agent_sessions(config, params):
    """List AI agent sessions. The route has no host filter: SensorId and
    AIAgentIds are never populated upstream, so sessions cannot be scoped to
    one agent or host -- group by Product instead."""
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryAgentSessionsV1'],
        {'product': _normalize_product(params.get('product')),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(
        envelope, AgentSessionRecord,
        extras_of=lambda r: {'session_id': r.session_id,
                             'models_invoked': r.models_invoked,
                             'working_directory': r.working_directory})
    return _result(records, parsed, notices)


def get_agent_sessions(config, params):
    """Session details by session record id (the AIAgentSession entity key)."""
    _require(params, 'ids')
    ids = params.get('ids')
    if isinstance(ids, str):
        ids = [part.strip() for part in ids.split(',') if part.strip()]
    records, parsed = _records(
        _client(config).request('GET', ROUTES['entitiesAgentSessionsV1'], {'ids': ids}),
        AgentSessionRecord,
        extras_of=lambda r: {'session_id': r.session_id,
                             'models_invoked': r.models_invoked,
                             'working_directory': r.working_directory})
    return _result(records, parsed)


def list_agent_installations(config, params):
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryAgentInstallationsV1'],
        {'sensor_id': params.get('sensor_id'),
         'product': _normalize_product(params.get('product')),
         'hostname': params.get('hostname'),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, InstallationRecord)
    return _result(records, parsed, notices)


def get_agent_installations(config, params):
    _require(params, 'ids')
    ids = params.get('ids')
    if isinstance(ids, str):
        ids = [part.strip() for part in ids.split(',') if part.strip()]
    records, parsed = _records(
        _client(config).request('GET', ROUTES['entitiesAgentInstallationsV1'], {'ids': ids}),
        InstallationRecord)
    return _result(records, parsed)


def list_os_users(config, params):
    """OS users that ran AI agents, keyed on Aid + Username."""
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryAgentOSUsersV1'],
        {'aid': params.get('aid'),
         'username': params.get('username'),
         'object_sid': params.get('object_sid'),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, OsUserRecord)
    return _result(records, parsed, notices)


def get_os_user(config, params):
    """One OS user record; the entity is keyed on aid + username."""
    _require(params, 'aid', 'username')
    record = _single(
        _client(config).request('GET', ROUTES['entitiesAgentOSUsersV1'],
                                {'aid': _text(params.get('aid'), 'aid'),
                                 'username': _text(params.get('username'), 'username')}),
        OsUserRecord, 'OS user')
    return {'record': record}


def list_mcp_server_names(config, params):
    """MCP server names seen in the environment; fleet-wide, no agent filter."""
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryMcpServerNamesV1'],
        {'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, McpServerRecord,
                               extras_of=lambda r: {'server_name': r.server_name})
    return _result(records, parsed, notices)


def list_model_names(config, params):
    """AI model names; the only server-side filter is time_range."""
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryModelNamesV1'],
        {'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, ModelNameRecord,
                               extras_of=lambda r: {'model_name': r.model_name})
    return _result(records, parsed, notices)


# ---------------------------------------------------------------------------
# tools and skills
# ---------------------------------------------------------------------------

def list_tools(config, params):
    """AI tool inventory (AITool). Rows are flat and host-scoped; for the
    invocations a host actually made, prefer list_tool_usage."""
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryToolsV1'],
        {'sensor_id': params.get('sensor_id'),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, ToolRecord)
    return _result(records, parsed, notices)


def get_tools(config, params):
    _require(params, 'ids')
    ids = params.get('ids')
    if isinstance(ids, str):
        ids = [part.strip() for part in ids.split(',') if part.strip()]
    records, parsed = _records(
        _client(config).request('GET', ROUTES['entitiesToolsV1'], {'ids': ids}),
        ToolRecord)
    return _result(records, parsed)


def list_tool_usage(config, params):
    """AI tool invocations (LogScale AgenticToolRequest).

    Defaults to a 2-hour window because that is what the API does -- widen
    time_range explicitly to look further back (7 days maximum). tool_name is
    exact and case-sensitive ('Bash', not 'bash'); the event store and the
    tool catalog can differ in case.
    """
    limit, offset = _page(params, default_limit=100)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryToolUsageV1'],
        {'tool_name': params.get('tool_name'),
         'aid': params.get('aid'),
         'session_id': params.get('session_id'),
         'time_range': _time_range(params.get('time_range'), LOGSCALE_DEFAULT_WINDOW),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, ToolUsageRecord)
    return _result(records, parsed, notices)


def list_skills(config, params):
    limit, offset = _page(params)
    notices = []
    envelope = _client(config).query(
        ROUTES['querySkillsV1'],
        {'name_filter': params.get('name_filter'),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, SkillRecord)
    return _result(records, parsed, notices)


def get_skills(config, params):
    _require(params, 'ids')
    ids = params.get('ids')
    if isinstance(ids, str):
        ids = [part.strip() for part in ids.split(',') if part.strip()]
    records, parsed = _records(
        _client(config).request('GET', ROUTES['entitiesSkillsV1'], {'ids': ids}),
        SkillRecord)
    return _result(records, parsed)


def list_skill_usage(config, params):
    """Per-invocation skill events (LogScale). Default window 2h, max 7d."""
    limit, offset = _page(params, default_limit=100)
    notices = []
    envelope = _client(config).query(
        ROUTES['querySkillUsageV1'],
        {'name': params.get('name'),
         'aid': params.get('aid'),
         'session_id': params.get('session_id'),
         'time_range': _time_range(params.get('time_range'), LOGSCALE_DEFAULT_WINDOW),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, SkillUsageRecord)
    return _result(records, parsed, notices)


# ---------------------------------------------------------------------------
# session activity: executions, prompts, agentic graph
# ---------------------------------------------------------------------------

def list_executions(config, params):
    """AI agent process executions with model + token counts
    (LogScale AgenticSessionStart). Only route that reports token usage."""
    limit, offset = _page(params, default_limit=100)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryExecutionsV1'],
        {'session_id': params.get('session_id'),
         'aid': params.get('aid'),
         'time_range': _time_range(params.get('time_range'), LOGSCALE_DEFAULT_WINDOW),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, ExecutionRecord)
    return _result(records, parsed, notices)


def get_execution_detail(config, params):
    """Execution detail for one session (AgenticSessionId UUID), optionally
    narrowed to one context process."""
    _require(params, 'session_id')
    record = _single(
        _client(config).request(
            'GET', ROUTES['entitiesExecutionsV1'],
            {'id': _text(params.get('session_id'), 'session_id'),
             'context_process_id': params.get('context_process_id')}),
        ExecutionRecord, 'execution')
    return {'record': record}


def list_prompts(config, params):
    """AI prompts within a session or host (LogScale). timestamp arrives as
    epoch milliseconds encoded as a string; the model coerces it to int."""
    limit, offset = _page(params, default_limit=100)
    notices = []
    envelope = _client(config).query(
        ROUTES['queryPromptsV1'],
        {'session_id': params.get('session_id'),
         'aid': params.get('aid'),
         'time_range': _time_range(params.get('time_range'), LOGSCALE_DEFAULT_WINDOW),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(envelope, PromptRecord)
    return _result(records, parsed, notices)


def get_session_activity(config, params):
    """ThreatGraph activity for one or more AI sessions (tools, models,
    processes, MCP servers as edges). Accepts AgenticSessionId UUIDs or full
    vertex keys (aisess:{aid}:{uuid}); the server resolves either."""
    _require(params, 'ids')
    ids = params.get('ids')
    if isinstance(ids, str):
        ids = [part.strip() for part in ids.split(',') if part.strip()]
    return _graph_result(
        _client(config).request('GET', ROUTES['entitiesSessionActivityV1'], {'ids': ids}))


def get_process_tree(config, params):
    """Spawned process tree for an AI session. depth is 1-3, default 2."""
    _require(params, 'session_id')
    depth = _int_param(params.get('depth'), 'depth', default=2, minimum=1, maximum=3)
    return _graph_result(
        _client(config).request('GET', ROUTES['entitiesProcessTreeV1'],
                                {'id': _text(params.get('session_id'), 'session_id'),
                                 'depth': depth}))


def get_network_events(config, params):
    """Outbound network connections from an AI session's processes."""
    _require(params, 'session_id')
    return _graph_result(
        _client(config).request('GET', ROUTES['entitiesNetworkEventsV1'],
                                {'id': _text(params.get('session_id'), 'session_id')}))


def get_file_events(config, params):
    """File write activity from an AI session's processes."""
    _require(params, 'session_id')
    return _graph_result(
        _client(config).request('GET', ROUTES['entitiesFileEventsV1'],
                                {'id': _text(params.get('session_id'), 'session_id')}))


def get_classified_file_access(config, params):
    """FDP classified file access for one process (pid:{aid}:{upid})."""
    _require(params, 'process_id')
    return _graph_result(
        _client(config).request('GET', ROUTES['entitiesClassifiedFileAccessV1'],
                                {'id': _text(params.get('process_id'), 'process_id')}))


# ---------------------------------------------------------------------------
# detections
# ---------------------------------------------------------------------------

def list_ai_detections(config, params):
    """Detections involving AI agent processes.

    agent_id takes the 32-hex SENSOR/host id (AIAgent.SensorId / aid), not the
    opaque AIAgent.Id -- the parameter name is misleading. The product filter
    takes the product name; the records answer with a numeric tag.
    """
    limit, offset = _page(params, default_limit=50)
    notices = []
    ui_base = falcon_ui_base(config)
    envelope = _client(config).query(
        ROUTES['queryDetectionsV1'],
        {'agent_id': params.get('agent_id'),
         'product': _normalize_product(params.get('product')),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    records, parsed = _records(
        envelope, DetectionRecord,
        extras_of=lambda r: {'falcon_ui_url': _falcon_ui_url(ui_base, r.composite_id)})
    return _result(records, parsed, notices)


def get_detection_scores(config, params):
    """Agentic Threat Score: max severity per agent id + product
    (aggregates/detections). Joining onto agents needs BOTH AgentId (the host
    sensor id) and AgenticProductTag; most rows are unattributed."""
    notices = []
    envelope = _client(config).aggregate(
        ROUTES['aggregateDetectionsV1'],
        {'agent_id': params.get('agent_id'),
         'product': _normalize_product(params.get('product')),
         'time_range': _time_range(params.get('time_range'), '7d')},
        notices=notices)
    rows, parsed = _buckets(envelope)
    records = [{'agent_id': row['bucket'].get('AgentId') or '',
                'product_tag': row['bucket'].get('AgenticProductTag') or '',
                'product_name': row['bucket'].get('AgenticProductTagName') or '',
                'max_detection_score': row['bucket'].get('maxDetectionScore', 0)}
               for row in rows]
    return _result(records, parsed, notices)


def falcon_ui_base(config):
    """Falcon console base (falcon.<domain>) for the configured cloud, or
    None when the base URL does not look like a CrowdStrike cloud."""
    from urllib.parse import urlparse
    base = GuardianClient(config).base_url
    host = urlparse(base).hostname or ''
    domain = host[len('api.'):] if host.startswith('api.') else host
    if not domain or 'crowdstrike' not in domain:
        return None
    return 'https://falcon.%s' % domain


def _falcon_ui_url(ui_base, composite_id):
    """Detection deep link into the Falcon console."""
    if not ui_base or not composite_id:
        return None
    return '%s/activity/detections/detection/%s' % (ui_base, composite_id)


# ---------------------------------------------------------------------------
# aggregates and fleet inventory
# ---------------------------------------------------------------------------

def _buckets(envelope):
    """Aggregate resources -> [{'label', 'count', 'bucket'}] rows, in reply order."""
    records, parsed = _records(envelope, AggregateBucket)
    rows = []
    for bucket in records:
        label = bucket.get('AgentProductName') or bucket.get('ProductName') \
            or bucket.get('Name') or bucket.get('SkillName') or bucket.get('key') or ''
        rows.append({'label': label, 'count': bucket['count'], 'bucket': bucket})
    return rows, parsed


def get_agent_product_counts(config, params):
    """Agent counts by product (aggregateAgentsV1). Capped at 500 groups."""
    notices = []
    envelope = _client(config).aggregate(
        ROUTES['aggregateAgentsV1'],
        {'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': _int_param(params.get('limit'), 'limit', default=500, maximum=500)},
        notices=notices)
    rows, parsed = _buckets(envelope)
    return _result([{'product': r['label'], 'count': r['count']} for r in rows],
                   parsed, notices)


def get_session_product_counts(config, params):
    """Session counts by product; counts arrive as JSON strings and are
    coerced to ints."""
    limit, offset = _page(params, default_limit=500)
    notices = []
    envelope = _client(config).aggregate(
        ROUTES['aggregateAgentSessionsV1'],
        {'product': _normalize_product(params.get('product')),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': limit, 'offset': offset},
        notices=notices)
    rows, parsed = _buckets(envelope)
    return _result([{'product': r['label'], 'count': r['count']} for r in rows],
                   parsed, notices)


def get_tool_name_counts(config, params):
    """Tool counts by name (aggregateToolsV1), optionally scoped to a host."""
    notices = []
    envelope = _client(config).aggregate(
        ROUTES['aggregateToolsV1'],
        {'sensor_id': params.get('sensor_id'),
         'time_range': _time_range(params.get('time_range'), '7d'),
         'limit': _int_param(params.get('limit'), 'limit', default=500, maximum=500)},
        notices=notices)
    rows, parsed = _buckets(envelope)
    return _result([{'tool': r['label'], 'count': r['count']} for r in rows],
                   parsed, notices)


def get_skill_name_counts(config, params):
    """Skill usage counts by name (aggregateSkillsV1)."""
    notices = []
    envelope = _client(config).aggregate(
        ROUTES['aggregateSkillsV1'],
        {'name_filter': params.get('name_filter'),
         'time_range': _time_range(params.get('time_range'), '7d')},
        notices=notices)
    rows, parsed = _buckets(envelope)
    return _result([{'skill': r['label'], 'count': r['count']} for r in rows],
                   parsed, notices)


def get_tool_usage_counts(config, params):
    """Tool invocation counts by name from LogScale events (session-scoped
    filters). Default window 2h, max 7d."""
    notices = []
    envelope = _client(config).aggregate(
        ROUTES['aggregateToolUsageV1'],
        {'session_id': params.get('session_id'),
         'aid': params.get('aid'),
         'time_range': _time_range(params.get('time_range'), LOGSCALE_DEFAULT_WINDOW)},
        notices=notices)
    rows, parsed = _buckets(envelope)
    return _result([{'tool': r['label'], 'count': r['count']} for r in rows],
                   parsed, notices)


def get_skill_usage_counts(config, params):
    """Skill invocation counts by name from LogScale events."""
    notices = []
    envelope = _client(config).aggregate(
        ROUTES['aggregateSkillUsageV1'],
        {'session_id': params.get('session_id'),
         'aid': params.get('aid'),
         'time_range': _time_range(params.get('time_range'), LOGSCALE_DEFAULT_WINDOW)},
        notices=notices)
    rows, parsed = _buckets(envelope)
    return _result([{'skill': r['label'], 'count': r['count']} for r in rows],
                   parsed, notices)


def get_fleet_inventory(config, params):
    """Fleet snapshot across the five aggregates: agents and sessions by
    product, tools by name, skills by name, and a detection rollup.

    Agents-by-product counts agents; sessions-by-product counts logical
    AIAgentSession rows -- different metrics, do not relabel one as the other.
    Counts can arrive as JSON strings; everything is coerced here.
    """
    time_range = _time_range(params.get('time_range'), '7d')
    product = _normalize_product(params.get('product'))
    client = _client(config)
    notices = []

    agents_env = client.aggregate(ROUTES['aggregateAgentsV1'],
                                  {'time_range': time_range, 'limit': 500}, notices=notices)
    sessions_env = client.aggregate(ROUTES['aggregateAgentSessionsV1'],
                                    {'time_range': time_range, 'limit': 500}, notices=notices)
    tools_env = client.aggregate(ROUTES['aggregateToolsV1'],
                                 {'time_range': time_range, 'limit': 500}, notices=notices)
    skills_env = client.aggregate(ROUTES['aggregateSkillsV1'],
                                  {'time_range': time_range}, notices=notices)
    detections_env = client.aggregate(ROUTES['aggregateDetectionsV1'],
                                      {'agent_id': params.get('agent_id'),
                                       'product': product,
                                       'time_range': time_range}, notices=notices)

    def _counts(envelope, label_key):
        rows = []
        for raw in envelope.get('resources') or []:
            bucket = AggregateBucket.model_validate(raw)
            label = bucket.bucket_label() or label_key
            rows.append({'name': label, 'count': bucket.count})
        rows.sort(key=lambda r: (-r['count'], r['name']))
        return rows

    agents = _counts(agents_env, 'unknown product')
    sessions = _counts(sessions_env, 'unknown product')
    tools = _counts(tools_env, 'unknown tool')
    skills = _counts(skills_env, 'unknown skill')

    worst = 0
    worst_rows = []
    for raw in detections_env.get('resources') or []:
        bucket = AggregateBucket.model_validate(raw)
        worst = max(worst, bucket.max_detection_score)
        if bucket.max_detection_score:
            worst_rows.append({'agent_id': bucket.agent_id,
                               'product': bucket.agentic_product_tag_name or bucket.agentic_product_tag or '',
                               'max_detection_score': bucket.max_detection_score})
    worst_rows.sort(key=lambda r: -r['max_detection_score'])

    return {
        'time_range': time_range,
        'agents_by_product': agents,
        'sessions_by_product': sessions,
        'tools_by_name': tools,
        'skills_by_name': skills,
        'detections': {'max_detection_score': worst,
                       'by_agent': worst_rows[:20],
                       'truncated': len(detections_env.get('resources') or []) >= 500},
        'notices': notices,
    }


# ---------------------------------------------------------------------------
# dropdown populator (hidden operation)
# ---------------------------------------------------------------------------

def list_ai_product_options(config, params):
    """Friendly AI product names for the product dropdowns.

    Returns plain strings (the step editor renders objects as [object Object]).
    Buckets keyed by an unresolved numeric tag are left out: the product input
    wants a name, and an unknown name is a 400.
    """
    envelope = _client(config).aggregate(ROUTES['aggregateAgentsV1'],
                                         {'time_range': '90d', 'limit': 500})
    names = []
    for raw in envelope.get('resources') or []:
        bucket = AggregateBucket.model_validate(raw)
        name = bucket.product_name or ''
        if name:
            names.append(name)
    return sorted(set(names))


# ---------------------------------------------------------------------------
# ingestion
# ---------------------------------------------------------------------------

def ingest_ai_detections(config, params, **kwargs):
    """Fetch AI-agent detections and map them to FortiSOAR alert dicts.

    Called by the fetch playbook of the Data Ingestion wizard. Params:
    time_range (default 24h), product, agent_id (32-hex sensor id),
    severity_min (0-100), max_records (default 200, cap 5000).
    """
    max_records = _int_param(params.get('max_records'), 'max_records',
                             default=200, minimum=1, maximum=MAX_TOTAL_RECORDS)
    severity_min = _int_param(params.get('severity_min'), 'severity_min',
                              default=0, minimum=0, maximum=100)
    notices = []
    ui_base = falcon_ui_base(config)
    envelope = _client(config).query(
        ROUTES['queryDetectionsV1'],
        {'agent_id': params.get('agent_id'),
         'product': _normalize_product(params.get('product')),
         'time_range': _time_range(params.get('time_range'), INGESTION_DEFAULT_WINDOW),
         'limit': 100, 'offset': 0},
        notices=notices)
    records, parsed = _records(envelope, DetectionRecord)
    alerts = []
    for raw, record in zip((envelope.get('resources') or []), records):
        if severity_min and record['Severity'] < severity_min:
            continue
        alerts.append(map_detection_to_alert(raw, record, _falcon_ui_url(ui_base, record['CompositeId'])))
        if len(alerts) >= max_records:
            break
    logger.info('Fetched %d Guardian detection(s) for ingestion', len(alerts))
    return {'alerts': alerts, 'count': len(alerts), 'notices': notices}


# ---------------------------------------------------------------------------
# dispatch
# ---------------------------------------------------------------------------

operations = {
    'list_ai_agents': list_ai_agents,
    'get_ai_agent': get_ai_agent,
    'list_agent_sessions': list_agent_sessions,
    'get_agent_sessions': get_agent_sessions,
    'list_agent_installations': list_agent_installations,
    'get_agent_installations': get_agent_installations,
    'list_os_users': list_os_users,
    'get_os_user': get_os_user,
    'list_tools': list_tools,
    'get_tools': get_tools,
    'list_tool_usage': list_tool_usage,
    'list_skills': list_skills,
    'get_skills': get_skills,
    'list_skill_usage': list_skill_usage,
    'list_mcp_server_names': list_mcp_server_names,
    'list_model_names': list_model_names,
    'list_executions': list_executions,
    'get_execution_detail': get_execution_detail,
    'list_prompts': list_prompts,
    'get_session_activity': get_session_activity,
    'get_process_tree': get_process_tree,
    'get_network_events': get_network_events,
    'get_file_events': get_file_events,
    'get_classified_file_access': get_classified_file_access,
    'list_ai_detections': list_ai_detections,
    'get_detection_scores': get_detection_scores,
    'get_agent_product_counts': get_agent_product_counts,
    'get_session_product_counts': get_session_product_counts,
    'get_tool_name_counts': get_tool_name_counts,
    'get_skill_name_counts': get_skill_name_counts,
    'get_tool_usage_counts': get_tool_usage_counts,
    'get_skill_usage_counts': get_skill_usage_counts,
    'get_fleet_inventory': get_fleet_inventory,
    'list_ai_product_options': list_ai_product_options,
    'ingest_ai_detections': ingest_ai_detections,
}
