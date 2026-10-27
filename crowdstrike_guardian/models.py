"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""
from typing import Any, Dict, Generic, List, Optional, TypeVar

from pydantic import BaseModel, ConfigDict, Field, field_validator

T = TypeVar('T')

# Guardian answers with the standard Falcon envelope; pydantic validates and
# coerces the parts this connector actually uses. Records keep unknown fields
# (extra='allow') so the playbook still receives everything the API returned,
# even where this module has not spelled a field out.


class _GuardianModel(BaseModel):
    """Base for Guardian records: tolerant of extra fields and of types that
    arrive as strings where they read as numbers (and the other way round).
    Coercion rules live in the per-model validators below."""

    model_config = ConfigDict(extra='allow', populate_by_name=True, str_strip_whitespace=False)


class FalconError(_GuardianModel):
    """One entry of the envelope's errors array."""
    code: int = 0
    message: str = ''
    type: Optional[str] = None


class Pagination(_GuardianModel):
    limit: int = 0
    offset: int = 0
    total: Optional[int] = None


class FalconMeta(_GuardianModel):
    pagination: Optional[Pagination] = None
    query_time: Optional[float] = None
    trace_id: Optional[str] = None


class FalconEnvelope(_GuardianModel, Generic[T]):
    """{"meta": {...}, "resources": [...], "errors": []} -- every /aidr reply."""

    meta: Optional[FalconMeta] = None
    resources: List[T] = Field(default_factory=list)
    errors: List[FalconError] = Field(default_factory=list)

    @property
    def error_messages(self):
        return [e.message for e in self.errors if e.message]

    @property
    def pagination(self):
        return self.meta.pagination if self.meta else None


def _as_int(value, default=0):
    """Aggregate counts arrive as JSON strings on some routes ('7') and as
    numbers on others; token counts are plain numbers. Coerce, never raise."""
    if value is None or value == '':
        return default
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return default


def _as_str(value):
    """Product tag IDs arrive as JSON strings from the entity queries and as
    JSON ints from the aggregates (0 = unattributed). Normalize both to str so
    a join between the two sides cannot silently miss."""
    if value is None:
        return ''
    return str(value)


# ---------------------------------------------------------------------------
# entity store records
# ---------------------------------------------------------------------------

class AgentRecord(_GuardianModel):
    """AIAgent. `Id` is the opaque record token (entities/agents takes it);
    `SensorId` is the 32-hex HOST id (aid) many other routes filter on."""
    id: str = Field(default='', alias='Id')
    agent_ids: List[str] = Field(default_factory=list, alias='AgentIds')
    sensor_id: str = Field(default='', alias='SensorId')
    agent_name: str = Field(default='', alias='AgentName')
    agent_product: str = Field(default='', alias='AgentProduct')
    agent_product_name: str = Field(default='', alias='AgentProductName')
    hostname: str = Field(default='', alias='Hostname')
    spiffe_id: Optional[str] = Field(default=None, alias='SpiffeId')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')
    last_execution_time: Optional[str] = Field(default=None, alias='LastExecutionTime')
    last_inventory_time: Optional[str] = Field(default=None, alias='LastInventoryTime')

    @field_validator('agent_ids', mode='before')
    @classmethod
    def _ids_list(cls, value):
        if value is None:
            return []
        return value if isinstance(value, list) else [value]

    @field_validator('agent_product', mode='before')
    @classmethod
    def _product_str(cls, value):
        return _as_str(value)


class AgentSessionRecord(_GuardianModel):
    """AIAgentSession. SensorId/AIAgentIds are never populated upstream."""
    id: str = Field(default='', alias='Id')
    product: str = Field(default='', alias='Product')
    product_name: str = Field(default='', alias='ProductName')
    name: str = Field(default='', alias='Name')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')
    cim: Dict[str, Any] = Field(default_factory=dict, alias='Cim')

    @field_validator('product', mode='before')
    @classmethod
    def _product_str(cls, value):
        return _as_str(value)

    @property
    def session_id(self):
        cim = (self.cim or {}).get('AIAgentSession') or {}
        return cim.get('sessionId') or ''

    @property
    def models_invoked(self):
        cim = (self.cim or {}).get('AIAgentSession') or {}
        return cim.get('modelsInvoked') or []

    @property
    def working_directory(self):
        cim = (self.cim or {}).get('AIAgentSession') or {}
        return cim.get('workingDirectory') or ''


class InstallationRecord(_GuardianModel):
    """AIAgentInstallationView."""
    id: str = Field(default='', alias='Id')
    sensor_id: str = Field(default='', alias='SensorId')
    hostname: str = Field(default='', alias='Hostname')
    agent_name: str = Field(default='', alias='AgentName')
    agent_product: str = Field(default='', alias='AgentProduct')
    agent_product_name: str = Field(default='', alias='AgentProductName')
    agent_version: str = Field(default='', alias='AgentVersion')
    install_source: str = Field(default='', alias='InstallSource')
    declaration_path: Optional[str] = Field(default=None, alias='AgentDeclarationPath')
    binary_path: Optional[str] = Field(default=None, alias='BinaryPath')
    file_sha256: Optional[str] = Field(default=None, alias='FileSha256')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')

    @field_validator('agent_product', mode='before')
    @classmethod
    def _product_str(cls, value):
        return _as_str(value)


class OsUserRecord(_GuardianModel):
    """AIAgentOSUser, keyed on Aid + Username."""
    aid: str = Field(default='', alias='Aid')
    username: str = Field(default='', alias='Username')
    object_sid: Optional[str] = Field(default=None, alias='ObjectSid')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')


class ToolRecord(_GuardianModel):
    """AITool. Rows are flat; sensor_id is the host, not one agent."""
    id: str = Field(default='', alias='Id')
    name: str = Field(default='', alias='Name')
    sensor_id: str = Field(default='', alias='SensorId')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')


class SkillRecord(_GuardianModel):
    """AISkillFrontmatter."""
    id: str = Field(default='', alias='Id')
    skill_name: str = Field(default='', alias='SkillName')
    skill_description: str = Field(default='', alias='SkillDescription')
    skill_directory_hash: Optional[str] = Field(default=None, alias='SkillDirectoryHash')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')


class McpServerRecord(_GuardianModel):
    """MCPServerName; fleet-wide, no agent filter."""
    id: str = Field(default='', alias='Id')
    cim: Dict[str, Any] = Field(default_factory=dict, alias='Cim')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')

    @property
    def server_name(self):
        return (self.cim or {}).get('MCPServerName', {}).get('serverName') or ''


class ModelNameRecord(_GuardianModel):
    """AIModelName; the Id is a hashed dedup key, modelName is the name."""
    id: str = Field(default='', alias='Id')
    cim: Dict[str, Any] = Field(default_factory=dict, alias='Cim')
    last_used_time: Optional[str] = Field(default=None, alias='LastUsedTime')
    first_seen: Optional[str] = Field(default=None, alias='FirstSeen')
    last_seen: Optional[str] = Field(default=None, alias='LastSeen')

    @property
    def model_name(self):
        return (self.cim or {}).get('AIModelName', {}).get('modelName') or ''


# ---------------------------------------------------------------------------
# LogScale-backed event records
# ---------------------------------------------------------------------------

class ExecutionRecord(_GuardianModel):
    """AgenticSessionStart: one row per process a session spawned. The only
    source of model + token counts."""
    session_id: str = Field(default='', alias='AgenticSessionId')
    model: str = Field(default='', alias='AgenticModel')
    working_directory: Optional[str] = Field(default=None, alias='AgenticWorkingDirectory')
    input_tokens: int = Field(default=0, alias='AgenticInputTokens')
    output_tokens: int = Field(default=0, alias='AgenticOutputTokens')
    context_process_id: Optional[str] = Field(default=None, alias='ContextProcessId')
    process_tags: List[str] = Field(default_factory=list, alias='ProcessTags')
    aid: str = Field(default='', alias='aid')
    timestamp: Optional[int] = Field(default=None)

    @field_validator('input_tokens', 'output_tokens', mode='before')
    @classmethod
    def _tokens(cls, value):
        return _as_int(value)

    @field_validator('timestamp', mode='before')
    @classmethod
    def _epoch_ms(cls, value):
        if value in (None, ''):
            return None
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

    @field_validator('process_tags', mode='before')
    @classmethod
    def _tags(cls, value):
        if value is None:
            return []
        if isinstance(value, list):
            return [_as_str(v) for v in value]
        return [_as_str(value)]


class ToolUsageRecord(_GuardianModel):
    """AgenticToolRequest."""
    session_id: str = Field(default='', alias='AgenticSessionId')
    tool: Optional[str] = Field(default=None, alias='AgenticTool')
    tool_name: str = Field(default='', alias='AgenticToolName')
    tool_use_id: Optional[str] = Field(default=None, alias='AgenticToolUseId')
    path: Optional[str] = Field(default=None, alias='AgenticPath')
    description: Optional[str] = Field(default=None, alias='AgenticDescription')
    pattern: Optional[str] = Field(default=None, alias='AgenticPattern')
    query: Optional[str] = Field(default=None, alias='AgenticQuery')
    skill: Optional[str] = Field(default=None, alias='AgenticSkill')
    command_line: Optional[str] = Field(default=None, alias='CommandLine')
    url: Optional[str] = Field(default=None, alias='Url')
    aid: str = Field(default='', alias='aid')
    timestamp: Optional[int] = None

    @field_validator('timestamp', mode='before')
    @classmethod
    def _epoch_ms(cls, value):
        if value in (None, ''):
            return None
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


class SkillUsageRecord(_GuardianModel):
    """AgenticSkill rows on AgenticToolRequest events."""
    session_id: str = Field(default='', alias='AgenticSessionId')
    skill: str = Field(default='', alias='AgenticSkill')
    tool_use_id: Optional[str] = Field(default=None, alias='AgenticToolUseId')
    aid: str = Field(default='', alias='aid')
    timestamp: Optional[int] = None

    @field_validator('timestamp', mode='before')
    @classmethod
    def _epoch_ms(cls, value):
        if value in (None, ''):
            return None
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None


class PromptRecord(_GuardianModel):
    """AgenticUserPromptSubmit. The API's timestamp is epoch milliseconds
    encoded as a STRING; coerce before sorting."""
    prompt: str = Field(default='', alias='AgenticPrompt')
    session_id: str = Field(default='', alias='AgenticSessionId')
    aid: str = Field(default='', alias='aid')
    process_tags: List[str] = Field(default_factory=list, alias='ProcessTags')
    timestamp: Optional[int] = None

    @field_validator('timestamp', mode='before')
    @classmethod
    def _epoch_ms_string(cls, value):
        if value in (None, ''):
            return None
        try:
            return int(float(value))
        except (TypeError, ValueError):
            return None

    @field_validator('process_tags', mode='before')
    @classmethod
    def _tags(cls, value):
        if value is None:
            return []
        if isinstance(value, list):
            return [_as_str(v) for v in value]
        return [_as_str(value)]


# ---------------------------------------------------------------------------
# detections
# ---------------------------------------------------------------------------

class DetectionRecord(_GuardianModel):
    """Alert-backed detection involving AI agent processes. Severity and
    RiskScore are different 0-100 metrics. AgenticProductTag is null here
    where the aggregate spells unattributed as 0 -- both mean unattributed."""
    composite_id: str = Field(default='', alias='CompositeId')
    agent_id: str = Field(default='', alias='AgentId')
    name: str = Field(default='', alias='Name')
    product: Optional[str] = Field(default=None, alias='Product')
    severity: int = Field(default=0, alias='Severity')
    severity_name: str = Field(default='', alias='SeverityName')
    risk_score: int = Field(default=0, alias='RiskScore')
    status: str = Field(default='', alias='Status')
    tactic: Optional[str] = Field(default=None, alias='Tactic')
    technique: Optional[str] = Field(default=None, alias='Technique')
    assigned_to: Optional[str] = Field(default=None, alias='AssignedToName')
    sha256: Optional[str] = Field(default=None, alias='Sha256')
    data_domains: List[str] = Field(default_factory=list, alias='DataDomains')
    source_products: List[str] = Field(default_factory=list, alias='SourceProducts')
    source_hosts: List[Optional[str]] = Field(default_factory=list, alias='SourceHosts')
    user_names: List[Optional[str]] = Field(default_factory=list, alias='UserNames')
    has_agentic_process: bool = Field(default=False, alias='HasAgenticProcess')
    agentic_product_tag: Optional[str] = Field(default=None, alias='AgenticProductTag')
    agentic_product_tag_name: Optional[str] = Field(default=None, alias='AgenticProductTagName')
    created_timestamp: Optional[str] = Field(default=None, alias='CreatedTimestamp')
    timestamp: Optional[str] = Field(default=None, alias='Timestamp')

    @field_validator('severity', 'risk_score', mode='before')
    @classmethod
    def _score(cls, value):
        return _as_int(value)

    @field_validator('agentic_product_tag', mode='before')
    @classmethod
    def _tag(cls, value):
        # '0' and null are both "unattributed"; keep null for both.
        text = _as_str(value)
        return text if text and text != '0' else None

    @field_validator('data_domains', 'source_products', mode='before')
    @classmethod
    def _list(cls, value):
        return value if isinstance(value, list) else ([] if value in (None, '') else [value])


class AggregateBucket(_GuardianModel):
    """One group of an /aggregates response. The key field differs per route
    (AgentProduct, Product, Name, SkillName, AgentId...); keep the raw keys and
    coerce count, which arrives as a JSON string on some routes."""
    count: int = Field(default=0)
    key: Optional[str] = Field(default=None, alias='Key')
    name: Optional[str] = Field(default=None, alias='Name')
    skill_name: Optional[str] = Field(default=None, alias='SkillName')
    product_name: Optional[str] = Field(default=None, alias='AgentProductName')
    product_name_session: Optional[str] = Field(default=None, alias='ProductName')
    agent_id: Optional[str] = Field(default=None, alias='AgentId')
    agentic_product_tag: Optional[str] = Field(default=None, alias='AgenticProductTag')
    agentic_product_tag_name: Optional[str] = Field(default=None, alias='AgenticProductTagName')
    max_detection_score: int = Field(default=0, alias='maxDetectionScore')

    @field_validator('count', 'max_detection_score', mode='before')
    @classmethod
    def _count(cls, value):
        return _as_int(value)

    @field_validator('agentic_product_tag', 'agent_id', mode='before')
    @classmethod
    def _ids(cls, value):
        # 0 (int or str) is the aggregate's "unattributed" marker, not a tag.
        text = _as_str(value)
        return text if text and text != '0' else ''

    def bucket_label(self):
        """The displayable label whatever key field this route grouped on."""
        return self.product_name or self.product_name_session or self.name \
            or self.skill_name or self.key or self.agent_id or ''


# ---------------------------------------------------------------------------
# connector outputs
# ---------------------------------------------------------------------------

class InventorySummary(_GuardianModel):
    """Output of get_fleet_inventory: fleet rollup across the five aggregates."""
    time_range: str = ''
    agents_by_product: List[Dict[str, Any]] = Field(default_factory=list)
    sessions_by_product: List[Dict[str, Any]] = Field(default_factory=list)
    tools_by_name: List[Dict[str, Any]] = Field(default_factory=list)
    skills_by_name: List[Dict[str, Any]] = Field(default_factory=list)
    detections: Dict[str, Any] = Field(default_factory=dict)
    notices: List[str] = Field(default_factory=list)


def parse_envelope(payload, model):
    """Validate one API response into FalconEnvelope[model].

    `model=None` keeps resources as plain dicts (graph endpoints, whose shapes
    are vertex/edge graphs rather than flat records). A malformed payload is a
    ConnectorError-raising failure for the caller, not a silent empty result.
    """
    from connectors.core.connector import ConnectorError
    try:
        if model is None:
            return FalconEnvelope[Dict[str, Any]].model_validate(payload)
        return FalconEnvelope[model].model_validate(payload)
    except Exception as err:
        raise ConnectorError('Guardian returned an unexpected response shape: %s' % err)
