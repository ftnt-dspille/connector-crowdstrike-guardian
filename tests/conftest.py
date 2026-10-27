"""
Fixtures for the CrowdStrike Falcon Guardian connector tests.

* The FortiSOAR SDK modules are stubbed so the connector imports standalone.
* FakeGuardian replaces requests.request / requests.post: no network. It mints
  tokens like the real OAuth2 endpoint, answers every /aidr route from sample
  data (or a route the test registers), and records every call.
* Live tests (mark ``live``) hit a real tenant and are opt-in via env vars;
  the default run skips them.
"""

import json
import sys
import types
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(ROOT))

# --- stub FortiSOAR SDK modules so the connector imports standalone ---------


def _install_sdk_stubs():
    if "connectors" in sys.modules and hasattr(sys.modules["connectors"], "_guardian_stub"):
        return
    import logging

    def module(name, **attrs):
        mod = types.ModuleType(name)
        mod.__path__ = []
        mod.__dict__.update(attrs)
        sys.modules[name] = mod
        return mod

    class ConnectorError(Exception):
        pass

    class Connector:
        pass

    pkg = module("connectors", _guardian_stub=True)
    core = module("connectors.core")
    module(
        "connectors.core.connector",
        ConnectorError=ConnectorError,
        Connector=Connector,
        get_logger=lambda name: logging.getLogger(name),
    )
    pkg.core = core


_install_sdk_stubs()

from crowdstrike_guardian import client as client_module  # noqa: E402
from crowdstrike_guardian.constants import CLOUDS  # noqa: E402

SAMPLES = json.load(open(Path(__file__).resolve().parent / "fixtures" / "guardian_samples.json"))

AID = SAMPLES["agent"]["SensorId"]
AGENT_ID = SAMPLES["agent"]["Id"]
SESSION_UUID = SAMPLES["session"]["Cim"]["AIAgentSession"]["sessionId"]


class Reply:
    def __init__(self, status=200, body=None, headers=None, text=None):
        self.status_code = status
        self._body = body
        self.headers = headers or {}
        if text is not None:
            self.content = text.encode()
            self.text = text
        elif body is None:
            self.content, self.text = b"", ""
        else:
            self.text = json.dumps(body)
            self.content = self.text.encode()
        self.reason = {
            200: "OK",
            201: "Created",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            429: "Too Many Requests",
            500: "Internal Server Error",
            503: "Service Unavailable",
            504: "Gateway Timeout",
        }.get(status, "Status")

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        if self._body is None:
            raise ValueError("no body")
        return self._body


class Call:
    def __init__(self, method, url, kwargs):
        self.method = method
        self.url = url
        self.params = kwargs.get("params") or {}
        self.headers = kwargs.get("headers") or {}
        self.data = kwargs.get("data")
        self.verify = kwargs.get("verify")
        self.timeout = kwargs.get("timeout")
        self.token = (self.headers.get("Authorization") or "").replace("Bearer ", "")
        # path relative to the API host
        self.path = "/" + url.split("://", 1)[1].split("/", 1)[1] if "://" in url else url


def envelope(resources, total=None, limit=50, offset=0, errors=None):
    """A standard Falcon envelope."""
    return {
        "meta": {
            "pagination": {
                "limit": limit,
                "offset": offset,
                "total": len(resources) if total is None else total,
            },
            "query_time": 0.05,
            "trace_id": "trace-test-1",
        },
        "resources": resources,
        "errors": errors or [],
    }


class FakeGuardian:
    """Stateful mock of the CrowdStrike API surface the connector touches."""

    def __init__(self):
        self.calls = []
        self.token_mints = 0
        self._routes = {}
        self._default_minter()

    # -- wiring ---------------------------------------------------------

    def route(
        self, method, path, status=200, body=None, resources=None, total=None, limit=50, offset=0, errors=None
    ):
        """Register (or override) one route."""
        self._routes[(method.upper(), path)] = {
            "status": status,
            "body": body,
            "resources": resources,
            "total": total,
            "limit": limit,
            "offset": offset,
            "errors": errors,
        }

    def route_error(self, method, path, status, message, code=None, error_type="cs"):
        self._routes[(method.upper(), path)] = {
            "status": status,
            "body": {"errors": [{"code": code or status, "message": message, "type": error_type}]},
        }

    def calls_to(self, path):
        return [c for c in self.calls if c.path == path and c.method == "GET"]

    # -- request entry point --------------------------------------------

    def request(self, method, url, **kwargs):
        call = Call(method, url, kwargs)
        self.calls.append(call)
        if call.path == "/oauth2/token" and call.method == "POST":
            route = self._routes.get(("POST", "/oauth2/token"))
            if route is not None:
                return Reply(route["status"], route["body"])
            return self._token_reply(call)
        auth = call.headers.get("Authorization") or ""
        if not auth.startswith("Bearer "):
            return Reply(401, {"errors": [{"code": 401, "message": "missing bearer token"}]})
        if not auth.endswith(self._valid_token()):
            return Reply(401, {"errors": [{"code": 401, "message": "invalid access token"}]})
        route = self._routes.get((call.method, call.path))
        if route is None:
            route = self._default_route(call)
        if route is None:
            return Reply(
                404, {"errors": [{"code": 404, "message": f"unhandled route: {call.method} {call.path}"}]}
            )
        status = route["status"]
        if status >= 400:
            body = (
                route["body"]
                if route["body"] is not None
                else {"errors": [{"code": status, "message": "request failed"}]}
            )
            return Reply(status, body)
        if route["body"] is not None:
            return Reply(status, route["body"])
        return Reply(
            status,
            envelope(
                route["resources"] or [],
                total=route["total"],
                limit=route["limit"],
                offset=route["offset"],
                errors=route["errors"],
            ),
        )

    # -- token ------------------------------------------------------------

    def _default_minter(self):
        self._minter = self._default_mint

    def _default_mint(self, call):
        self.token_mints += 1
        if (
            not call.data
            or call.data.get("grant_type") != "client_credentials"
            or not call.data.get("client_id")
            or not call.data.get("client_secret")
        ):
            return Reply(400, {"errors": [{"code": 400, "message": "invalid client_id or client_secret"}]})
        return Reply(
            201,
            {"access_token": f"fake-token-{self.token_mints}", "expires_in": 1799, "token_type": "bearer"},
        )

    def _valid_token(self):
        return f"fake-token-{self.token_mints}"

    def _token_reply(self, call):
        return self._minter(call)

    # -- default routes -----------------------------------------------------

    def _default_route(self, call):
        """Answer any /aidr route the test did not override, from fixtures."""
        path = call.path
        params = call.params
        ok = lambda body: {"status": 200, "body": body}  # noqa: E731

        if path == "/aidr/queries/agents/v1":
            records = [SAMPLES["agent"], SAMPLES["agent_second"]]
            if params.get("product"):
                records = [r for r in records if _product_matches(r, params["product"])]
            if params.get("hostname"):
                records = [r for r in records if r["Hostname"] == params["hostname"]]
            return ok(_paged(records, params))

        if path == "/aidr/entities/agents/v1":
            ids = _ids(params)
            return ok(envelope([r for r in (SAMPLES["agent"], SAMPLES["agent_second"]) if r["Id"] in ids]))

        if path == "/aidr/queries/agent-sessions/v1":
            return ok(_paged([SAMPLES["session"]], params))

        if path == "/aidr/entities/agent-sessions/v1":
            ids = _ids(params)
            return ok(envelope([SAMPLES["session"]] if SAMPLES["session"]["Id"] in ids else []))

        if path == "/aidr/queries/agent-installations/v1":
            return ok(_paged([SAMPLES["installation"]], params))

        if path == "/aidr/entities/agent-installations/v1":
            ids = _ids(params)
            return ok(envelope([SAMPLES["installation"]] if SAMPLES["installation"]["Id"] in ids else []))

        if path == "/aidr/queries/agent-os-users/v1":
            return ok(_paged([SAMPLES["os_user"]], params))

        if path == "/aidr/entities/agent-os-users/v1":
            if params.get("aid") == AID and params.get("username") == "alice":
                return ok(envelope([SAMPLES["os_user"]]))
            return ok(envelope([]))

        if path == "/aidr/queries/tools/v1":
            return ok(_paged([SAMPLES["tool"]], params))

        if path == "/aidr/entities/tools/v1":
            ids = _ids(params)
            return ok(envelope([SAMPLES["tool"]] if SAMPLES["tool"]["Id"] in ids else []))

        if path == "/aidr/queries/skills/v1":
            records = [SAMPLES["skill"]]
            if params.get("name_filter"):
                records = [r for r in records if params["name_filter"].lower() in r["SkillName"].lower()]
            return ok(_paged(records, params))

        if path == "/aidr/entities/skills/v1":
            ids = _ids(params)
            return ok(envelope([SAMPLES["skill"]] if SAMPLES["skill"]["Id"] in ids else []))

        if path == "/aidr/queries/mcp-server-names/v1":
            return ok(_paged([SAMPLES["mcp_server"]], params))

        if path == "/aidr/queries/model-names/v1":
            return ok(_paged([SAMPLES["model_name"]], params))

        if path == "/aidr/queries/executions/v1":
            return ok(_paged([SAMPLES["execution"], SAMPLES["execution_string_counts"]], params))

        if path == "/aidr/entities/executions/v1":
            if params.get("id") == SESSION_UUID:
                return ok(envelope([SAMPLES["execution"]]))
            return ok(envelope([]))

        if path == "/aidr/queries/tool-usage/v1":
            records = [SAMPLES["tool_usage"], SAMPLES["tool_usage_lowercase"]]
            if params.get("tool_name"):
                records = [r for r in records if r["AgenticToolName"] == params["tool_name"]]
            return ok(_paged(records, params))

        if path == "/aidr/queries/skill-usage/v1":
            records = [SAMPLES["skill_usage"]]
            if params.get("name"):
                records = [r for r in records if r["AgenticSkill"] == params["name"]]
            return ok(_paged(records, params))

        if path == "/aidr/queries/prompts/v1":
            return ok(_paged([SAMPLES["prompt"]], params))

        if path == "/aidr/queries/detections/v1":
            records = [SAMPLES["detection"], SAMPLES["detection_unattributed"]]
            if params.get("product"):
                records = [r for r in records if _product_matches(r, params["product"])]
            return ok(_paged(records, params))

        if path == "/aidr/aggregates/agents/v1":
            return ok(envelope(SAMPLES["aggregate_agents"]))

        if path == "/aidr/aggregates/agent-sessions/v1":
            return ok(envelope(SAMPLES["aggregate_sessions"]))

        if path == "/aidr/aggregates/tools/v1":
            return ok(envelope(SAMPLES["aggregate_tools"]))

        if path == "/aidr/aggregates/skills/v1":
            return ok(envelope(SAMPLES["aggregate_skills"]))

        if path == "/aidr/aggregates/tool-usage/v1":
            return ok(envelope(SAMPLES["aggregate_tool_usage"]))

        if path == "/aidr/aggregates/skill-usage/v1":
            return ok(envelope(SAMPLES["aggregate_skill_usage"]))

        if path == "/aidr/aggregates/detections/v1":
            return ok(envelope(SAMPLES["aggregate_detections"]))

        if path == "/aidr/entities/session-activity/v1":
            return ok(envelope([SAMPLES["graph_session_activity"]]))

        if path == "/aidr/entities/process-tree/v1":
            return ok(envelope([SAMPLES["graph_process_tree"]]))

        if path == "/aidr/entities/network-events/v1":
            return ok(envelope([SAMPLES["graph_network_events"]]))

        if path == "/aidr/entities/file-events/v1":
            return ok(envelope([SAMPLES["graph_file_events"]]))

        if path == "/aidr/entities/classified-file-access/v1":
            return ok(envelope([SAMPLES["graph_classified_file_access"]]))

        return None


def _product_matches(record, product):
    """Entity sources answer with tag ids plus a friendly Name sibling."""
    name = record.get("AgentProductName") or record.get("ProductName") or record.get("AgenticProductTagName")
    return bool(name) and name.upper().replace(" ", "_") == product.upper()


def _ids(params):
    raw = params.get("ids") or []
    if isinstance(raw, str):
        return [part for part in raw.split(",") if part]
    return list(raw)


def _paged(records, params):
    """Honor limit/offset like the API does (a short page ends the data)."""
    limit = int(params.get("limit") or 50)
    offset = int(params.get("offset") or 0)
    page = records[offset : offset + limit]
    return envelope(page, limit=limit, offset=offset, total=offset + len(page))


# ---------------------------------------------------------------------------
# pytest fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def fake():
    return FakeGuardian()


@pytest.fixture
def mock_api(fake, monkeypatch):
    """Point the connector's HTTP at FakeGuardian (it handles the token mint too)."""
    monkeypatch.setattr(client_module.requests, "request", fake.request)
    return fake


@pytest.fixture
def config():
    return {
        "cloud": "https://api.crowdstrike.com",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "verify_ssl": False,
        "timeout": 10,
    }


@pytest.fixture(autouse=True)
def _fresh_tokens():
    """The client caches minted tokens in a module dict; isolate every test."""
    client_module._TOKENS.clear()
    yield
    client_module._TOKENS.clear()


@pytest.fixture
def cloud_options():
    return CLOUDS
