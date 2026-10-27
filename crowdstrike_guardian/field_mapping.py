"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""
from datetime import datetime, timezone

# Every value here MUST be a member of the FortiSOAR Severity picklist; an
# unmapped value makes the ingestion playbook's resolveRange miss and the
# alert POST fail with a picklist 400. Falcon SeverityName is upper-case.
SEVERITY_MAP = {
    'CRITICAL': 'Critical',
    'HIGH': 'High',
    'MEDIUM': 'Medium',
    'LOW': 'Low',
    'INFORMATIONAL': 'Minimal',
    'UNSPECIFIED': 'Minimal',
    'NONE': 'Minimal',
}

# Fallback when SeverityName is absent: Falcon's numeric Severity runs 0-100.
SEVERITY_NUMERIC_BUCKETS = (
    (19, 'Minimal'),
    (39, 'Low'),
    (59, 'Medium'),
    (79, 'High'),
)

# Falcon detection status (lower-case in the API) to the FortiSOAR AlertState
# picklist.
STATUS_MAP = {
    'new': 'New',
    'in_progress': 'Open',
    'reopen': 'Open',
    'closed': 'Closed',
}


def resolve_severity(severity_name, severity_num=None):
    """Resolve a Falcon detection severity to a FortiSOAR picklist value."""
    if severity_name:
        mapped = SEVERITY_MAP.get(str(severity_name).strip().upper())
        if mapped:
            return mapped
    try:
        number = int(float(severity_num))
    except (TypeError, ValueError):
        return 'Minimal'
    for ceiling, label in SEVERITY_NUMERIC_BUCKETS:
        if number <= ceiling:
            return label
    return 'Critical'


def resolve_alert_state(status):
    text = str(status or '').strip().lower()
    return STATUS_MAP.get(text, 'New')


def _iso_to_epoch_seconds(value):
    """Falcon timestamps are ISO-8601 UTC ('2026-10-02T20:15:00Z').

    FortiSOAR's date columns are integer epoch *seconds*. Emitting both keeps
    date arithmetic in Python instead of routing an ISO string through a jinja
    date filter, which fails silently and leaves every alert timestamped at
    ingest time.
    """
    if not value:
        return None
    text = str(value).strip().replace('Z', '+00:00')
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return int(parsed.timestamp())


def _people(values):
    return ', '.join(str(v) for v in values or [] if v) or None


def map_detection_to_alert(raw, record=None, falcon_ui_url=None):
    """Map a Guardian detection to a FortiSOAR alert dict.

    `raw` is the API record as returned; `record` is the validated
    DetectionRecord dump (coerced numbers, normalized tags). Fields the API
    leaves null (AssignedToName, SourceHosts, UserNames) come out None rather
    than empty strings so the playbook's default filters behave.
    """
    record = record or raw or {}

    severity = resolve_severity(record.get('SeverityName'), record.get('Severity'))
    state = resolve_alert_state(record.get('Status'))
    composite_id = record.get('CompositeId') or ''
    tactic = record.get('Tactic') or None
    technique = record.get('Technique') or None

    description_parts = ['AI agent security detection from CrowdStrike Falcon Guardian.']
    description_parts.append('Severity: %s. Status: %s.' % (severity, record.get('Status') or state))
    product = record.get('AgenticProductTagName') or record.get('AgenticProductTag')
    if product:
        description_parts.append('AI product: %s.' % product)
    if record.get('AssignedToName'):
        description_parts.append('Assigned to: %s.' % record['AssignedToName'])
    if record.get('UserNames'):
        description_parts.append('Users: %s.' % _people(record.get('UserNames')))
    if record.get('SourceHosts'):
        description_parts.append('Hosts: %s.' % _people(record.get('SourceHosts')))
    if record.get('DataDomains'):
        description_parts.append('Data domains: %s.' % ', '.join(record['DataDomains']))
    if record.get('Sha256'):
        description_parts.append('SHA256: %s.' % record['Sha256'])
    if tactic:
        description_parts.append('MITRE tactic: %s.' % tactic)
    if technique:
        description_parts.append('MITRE technique: %s.' % technique)
    if falcon_ui_url:
        description_parts.append('Falcon console: %s' % falcon_ui_url)

    return {
        'external_id': composite_id or None,
        'name': record.get('Name') or 'CrowdStrike Guardian detection',
        'alert_state': state,
        'severity': severity,
        'category': 'AI Agent Security',
        'subcategory': tactic,
        'alert_type': 'CrowdStrike Guardian',
        'alert_generation_time': record.get('Timestamp'),
        'alert_generation_epoch': _iso_to_epoch_seconds(record.get('Timestamp')),
        'last_observed_time': record.get('CreatedTimestamp'),
        'last_observed_epoch': _iso_to_epoch_seconds(record.get('CreatedTimestamp')),
        'source_hostname': _people(record.get('SourceHosts')),
        'source_user': _people(record.get('UserNames')),
        'rule_name': technique,
        'rule_description': tactic,
        'description': ' '.join(description_parts),
        'risk_score': record.get('RiskScore'),
        'has_agentic_process': bool(record.get('HasAgenticProcess')),
        'agentic_product': product,
        'falcon_ui_url': falcon_ui_url,
        'raw_detection': raw,
    }
