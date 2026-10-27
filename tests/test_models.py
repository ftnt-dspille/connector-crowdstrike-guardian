"""The pydantic layer: envelope validation and the coercions the API needs."""

import pytest
from conftest import SAMPLES
from connectors.core.connector import ConnectorError

from crowdstrike_guardian.models import (
    AgentRecord,
    AggregateBucket,
    DetectionRecord,
    ExecutionRecord,
    FalconEnvelope,
    PromptRecord,
    parse_envelope,
)


def envelope_of(record):
    return {
        "meta": {"pagination": {"limit": 50, "offset": 0, "total": 1}},
        "resources": [record],
        "errors": [],
    }


class TestEnvelope:
    def test_parses_the_standard_envelope(self):
        parsed = parse_envelope(envelope_of(SAMPLES["agent"]), AgentRecord)
        assert len(parsed.resources) == 1
        assert parsed.resources[0].id == SAMPLES["agent"]["Id"]
        assert parsed.pagination.limit == 50

    def test_error_messages_are_reachable(self):
        payload = {
            "errors": [{"code": 403, "message": "scope missing", "type": "cs"}],
            "resources": [],
            "meta": None,
        }
        parsed = parse_envelope(payload, AgentRecord)
        assert parsed.error_messages == ["scope missing"]

    def test_unknown_shape_is_a_connector_error(self):
        with pytest.raises(ConnectorError):
            parse_envelope({"resources": "not-a-list"}, AgentRecord)

    def test_records_keep_unknown_fields(self):
        raw = dict(SAMPLES["agent"], SomeFutureField="x")
        parsed = parse_envelope(envelope_of(raw), AgentRecord)
        dumped = parsed.resources[0].model_dump(by_alias=True)
        assert dumped["SomeFutureField"] == "x"


class TestAgentRecord:
    def test_product_tag_id_arrives_as_string(self):
        record = AgentRecord.model_validate(SAMPLES["agent"])
        assert record.agent_product == "213584428666221"

    def test_product_tag_id_arriving_as_int_is_normalized(self):
        raw = dict(SAMPLES["agent"], AgentProduct=213584428666221)
        record = AgentRecord.model_validate(raw)
        assert record.agent_product == "213584428666221"
        assert record.agent_product_name == "Claude Code"

    def test_agent_ids_scalar_becomes_a_list(self):
        raw = dict(SAMPLES["agent"], AgentIds="abc123")
        record = AgentRecord.model_validate(raw)
        assert record.agent_ids == ["abc123"]

    def test_agent_ids_null_becomes_empty(self):
        raw = dict(SAMPLES["agent"], AgentIds=None)
        assert AgentRecord.model_validate(raw).agent_ids == []


class TestAgentSession:
    def test_nested_cim_is_surfaced(self):
        from crowdstrike_guardian.models import AgentSessionRecord

        record = AgentSessionRecord.model_validate(SAMPLES["session"])
        assert record.session_id == "eb5ca156-1128-44ab-b933-3154a36e8a54"
        assert "claude-sonnet-4-5" in record.models_invoked
        assert record.working_directory == "/home/alice/project"

    def test_missing_cim_degrades_to_empty(self):
        from crowdstrike_guardian.models import AgentSessionRecord

        record = AgentSessionRecord.model_validate({"Id": "x"})
        assert record.session_id == ""
        assert record.models_invoked == []


class TestExecution:
    def test_token_counts(self):
        record = ExecutionRecord.model_validate(SAMPLES["execution"])
        assert record.input_tokens == 12345
        assert record.output_tokens == 678

    def test_token_counts_arriving_as_strings(self):
        record = ExecutionRecord.model_validate(SAMPLES["execution_string_counts"])
        assert record.input_tokens == 2048
        assert record.output_tokens == 96

    def test_garbage_token_counts_do_not_raise(self):
        raw = dict(SAMPLES["execution"], AgenticInputTokens="many")
        assert ExecutionRecord.model_validate(raw).input_tokens == 0


class TestPrompt:
    def test_timestamp_is_epoch_millis_encoded_as_a_string(self):
        record = PromptRecord.model_validate(SAMPLES["prompt"])
        assert record.timestamp == 1769551100000
        assert record.prompt.startswith("Fix the failing import")

    def test_null_timestamp_stays_none(self):
        raw = dict(SAMPLES["prompt"], timestamp=None)
        assert PromptRecord.model_validate(raw).timestamp is None


class TestDetection:
    def test_scores_are_numbers(self):
        record = DetectionRecord.model_validate(SAMPLES["detection"])
        assert record.severity == 80
        assert record.risk_score == 65
        assert record.has_agentic_process is True

    def test_unattributed_tag_is_null_in_both_encodings(self):
        # queries/detections uses null; the aggregate uses 0.
        null_record = DetectionRecord.model_validate(SAMPLES["detection_unattributed"])
        assert null_record.agentic_product_tag is None
        zero = DetectionRecord.model_validate(dict(SAMPLES["detection_unattributed"], AgenticProductTag=0))
        assert zero.agentic_product_tag is None

    def test_scalar_domain_becomes_a_list(self):
        raw = dict(SAMPLES["detection"], DataDomains="Endpoint")
        assert DetectionRecord.model_validate(raw).data_domains == ["Endpoint"]


class TestAggregateBucket:
    def test_string_counts_are_coerced(self):
        bucket = AggregateBucket.model_validate(
            {"AgentProduct": "213584428666221", "AgentProductName": "Claude Code", "count": "3"}
        )
        assert bucket.count == 3
        assert bucket.bucket_label() == "Claude Code"

    def test_detection_score_bucket(self):
        bucket = AggregateBucket.model_validate(SAMPLES["aggregate_detections"][1])
        assert bucket.max_detection_score == 95
        assert bucket.agentic_product_tag == ""  # 0 means unattributed

    def test_garbage_count_degrades_to_zero(self):
        bucket = AggregateBucket.model_validate({"count": "several"})
        assert bucket.count == 0


class TestFalconEnvelopeGeneric:
    def test_generic_envelope_holds_dicts_for_graph_routes(self):
        parsed = parse_envelope(envelope_of(SAMPLES["graph_process_tree"]), None)
        assert parsed.resources[0]["root"]["name"] == "claude"
        assert isinstance(parsed, FalconEnvelope)
