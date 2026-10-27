"""The HTTP client: token lifecycle, retries, error hints, pagination, ladder."""

import time

import pytest
from conftest import Call, Reply, envelope
from connectors.core.connector import ConnectorError

from crowdstrike_guardian import client as client_module
from crowdstrike_guardian.client import GuardianClient, normalize_base_url


class TestBaseUrl:
    def test_cloud_dropdown_selects_the_host(self, config):
        config["cloud"] = "https://api.us-2.crowdstrike.com"
        assert GuardianClient(config).base_url == "https://api.us-2.crowdstrike.com"

    def test_custom_cloud_requires_base_url(self, config):
        config["cloud"] = "custom"
        config.pop("base_url", None)
        with pytest.raises(ConnectorError) as excinfo:
            normalize_base_url(config)
        assert "Base URL" in str(excinfo.value)

    def test_base_url_wins_over_the_dropdown(self, config):
        config["base_url"] = "https://api.eu-1.crowdstrike.com/"
        config["cloud"] = "https://api.us-2.crowdstrike.com"
        client = GuardianClient(config)
        assert client.base_url == "https://api.eu-1.crowdstrike.com"

    def test_scheme_is_added_when_missing(self, config):
        config["base_url"] = "api.crowdstrike.com"
        assert GuardianClient(config).base_url == "https://api.crowdstrike.com"

    def test_default_cloud(self, config):
        config.pop("cloud")
        assert GuardianClient(config).base_url == "https://api.crowdstrike.com"


class TestToken:
    def test_mints_once_and_reuses(self, mock_api, config):
        client = GuardianClient(config)
        client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        assert mock_api.token_mints == 1

    def test_mints_per_client_id(self, mock_api, config):
        GuardianClient(config).request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        config["client_id"] = "other-client"
        GuardianClient(config).request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        assert mock_api.token_mints == 2

    def test_expired_token_is_refreshed(self, mock_api, config):
        client = GuardianClient(config)
        client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        key = (client.base_url, client.client_id)
        token, _ = client_module._TOKENS[key]
        client_module._TOKENS[key] = (token, time.time() - 1)  # expired
        client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        assert mock_api.token_mints == 2

    def test_a_rejected_token_remints_once_then_succeeds(self, mock_api, config):
        client = GuardianClient(config)
        # Mint a token, then make the fake treat it as stale by bumping the
        # valid token: the 401 path must remint and retry, not fail.
        client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        mock_api.token_mints += 1  # the fake now accepts only the next token
        body = client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        assert body["resources"]
        # mint 1 = initial, mint 2 is the bump itself, mint 3 = the remint
        assert mock_api.token_mints == 3

    def test_missing_credentials_fail_before_any_request(self, mock_api, config):
        config.pop("client_secret")
        client = GuardianClient(config)
        with pytest.raises(ConnectorError) as excinfo:
            client.request("GET", "/aidr/queries/agents/v1", {})
        assert "Client ID and Client Secret" in str(excinfo.value)
        assert not mock_api.calls

    def test_bad_credentials_carry_the_api_message(self, mock_api, config):
        config["client_secret"] = "wrong"
        mock_api.route_error("POST", "/oauth2/token", 401, "invalid client_id or client_secret", code=401)
        client = GuardianClient(config)
        with pytest.raises(ConnectorError) as excinfo:
            client.request("GET", "/aidr/queries/agents/v1", {})
        assert "invalid client_id or client_secret" in str(excinfo.value)


class TestErrors:
    def test_error_message_is_surfaced(self, mock_api, config):
        mock_api.route_error(
            "GET", "/aidr/queries/agents/v1", 400, "Parameter product is not allowed", code=400
        )
        client = GuardianClient(config)
        with pytest.raises(ConnectorError) as excinfo:
            client.request("GET", "/aidr/queries/agents/v1", {"product": "nope"})
        message = str(excinfo.value)
        assert "Parameter product is not allowed" in message
        assert "names the parameter" in message  # the 400 hint

    def test_403_carries_the_scope_hint(self, mock_api, config):
        mock_api.route_error(
            "GET", "/aidr/queries/agents/v1", 403, "Client not authorized for AIDR scope", code=403
        )
        client = GuardianClient(config)
        with pytest.raises(ConnectorError) as excinfo:
            client.request("GET", "/aidr/queries/agents/v1", {})
        assert "AIDR: READ" in str(excinfo.value)

    def test_504_hint_points_at_the_window(self, mock_api, config):
        mock_api.route_error("GET", "/aidr/queries/executions/v1", 504, "query timed out", code=504)
        client = GuardianClient(config)
        with pytest.raises(ConnectorError) as excinfo:
            client.request("GET", "/aidr/queries/executions/v1", {"time_range": "7d"})
        assert "Narrow the Time Range" in str(excinfo.value)


class TestRetries:
    def test_429_is_retried_after_the_header(self, mock_api, config, monkeypatch):
        waits = []
        monkeypatch.setattr(client_module, "_sleep", waits.append)
        mock_api.route(
            "GET",
            "/aidr/queries/agents/v1",
            status=429,
            body={"errors": [{"code": 429, "message": "rate limited"}]},
        )
        client = GuardianClient(config)
        with pytest.raises(ConnectorError):
            client.request("GET", "/aidr/queries/agents/v1", {})
        assert len(waits) == client_module.MAX_ATTEMPTS - 1

    def test_502_is_retried_for_gets(self, mock_api, config, monkeypatch):
        waits = []
        monkeypatch.setattr(client_module, "_sleep", waits.append)
        # Pre-seed a valid token so the flaky 502 lands on the GET, not the mint.
        client = GuardianClient(config)
        mock_api.token_mints = 1
        client_module._TOKENS[(client.base_url, client.client_id)] = ("fake-token-1", time.time() + 600)
        responses = [
            Reply(502, {"errors": [{"code": 502, "message": "bad gateway"}]}),
            Reply(200, envelope([{"ok": True}])),
        ]
        state = {"n": 0}

        def flaky(method, url, **kwargs):
            result = responses[min(state["n"], len(responses) - 1)]
            state["n"] += 1
            return result

        monkeypatch.setattr(client_module.requests, "request", flaky)
        body = client.request("GET", "/aidr/queries/tools/v1", {})
        assert body["resources"] == [{"ok": True}]

    def test_remitted_token_is_used_after_401(self, mock_api, config):
        client = GuardianClient(config)
        client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        # Simulate the server invalidating the cached token mid-session.
        key = (client.base_url, client.client_id)
        client_module._TOKENS[key] = ("stale-token", time.time() + 600)
        body = client.request("GET", "/aidr/queries/agents/v1", {"limit": 1})
        assert body["resources"]


class TestWindowLadder:
    def test_narrowing_happens_on_504(self, mock_api, config):
        # Refuse everything wider than 24h on executions, then serve.
        def handler(method, url, **kwargs):
            call = Call(method, url, kwargs)
            if call.path == "/oauth2/token":
                return mock_api.request(method, url, **kwargs)
            if call.params.get("time_range") in ("7d", "30d"):
                return Reply(504, {"errors": [{"code": 504, "message": "query timed out"}]})
            return Reply(200, envelope([{"AgenticSessionId": "s1"}]))

        import crowdstrike_guardian.client as client_mod

        original = client_mod.requests.request
        client_mod.requests.request = handler  # patched by hand; restored below
        try:
            client = GuardianClient(config)
            notices = []
            body = client.query(
                "/aidr/queries/executions/v1", {"time_range": "30d", "limit": 10}, notices=notices
            )
            assert body["resources"] == [{"AgenticSessionId": "s1"}]
            assert any("30d" in n and "7d" in n for n in notices)
            assert any("7d" in n and "24h" in n for n in notices)
        finally:
            client_mod.requests.request = original

    def test_ladder_gives_up_at_the_floor(self, mock_api, config):
        mock_api.route_error("GET", "/aidr/queries/executions/v1", 504, "query timed out", code=504)
        client = GuardianClient(config)
        with pytest.raises(ConnectorError):
            client.query("/aidr/queries/executions/v1", {"time_range": "90d"})
        # 90d -> 7d -> 24h -> 6h -> 1h: four narrowing attempts then raise
        attempts = [c for c in mock_api.calls_to("/aidr/queries/executions/v1")]
        assert len(attempts) == 5

    def test_400_naming_time_range_narrows(self, mock_api, config):
        calls = []

        def handler(method, url, **kwargs):
            call = Call(method, url, kwargs)
            if call.path == "/oauth2/token":
                return mock_api.request(method, url, **kwargs)
            calls.append(call.params.get("time_range"))
            if call.params.get("time_range") == "30d":
                return Reply(
                    400, {"errors": [{"code": 400, "message": "time_range 30d exceeds the 7d maximum"}]}
                )
            return Reply(200, envelope([{"ok": 1}]))

        import crowdstrike_guardian.client as client_mod

        original = client_mod.requests.request
        client_mod.requests.request = handler
        try:
            client = GuardianClient(config)
            notices = []
            body = client.query("/aidr/queries/prompts/v1", {"time_range": "30d"}, notices=notices)
            assert body["resources"] == [{"ok": 1}]
            assert calls == ["30d", "7d"]
            assert notices
        finally:
            client_mod.requests.request = original

    def test_narrow_helper_ordering(self):
        assert GuardianClient._window_hours("7d") == 168.0
        assert GuardianClient._window_hours("2h") == 2.0
        assert GuardianClient._window_hours("30m") == 0.5
        assert GuardianClient._window_hours("nonsense") is None


class TestPagination:
    def test_stops_on_a_short_page(self, mock_api, config):
        client = GuardianClient(config)
        records = client.paginate("/aidr/queries/agents/v1", {"limit": 2})
        # the default route answers 2 agents with limit=2, then 0 on page 2
        assert len(records) == 2

    def test_walks_until_the_data_runs_out(self, mock_api, config):
        # Three agents' worth of data handed out two at a time.
        pages = [
            Reply(200, envelope([{"Id": "a1"}, {"Id": "a2"}], limit=2, offset=0)),
            Reply(200, envelope([{"Id": "a3"}], limit=2, offset=2)),
        ]

        def handler(method, url, **kwargs):
            call = Call(method, url, kwargs)
            if call.path == "/oauth2/token":
                return mock_api.request(method, url, **kwargs)
            return pages[min(call.params["offset"] // 2, len(pages) - 1)]

        import crowdstrike_guardian.client as client_mod

        original = client_mod.requests.request
        client_mod.requests.request = handler
        try:
            client = GuardianClient(config)
            records = client.paginate("/aidr/queries/agents/v1", {"limit": 2})
            assert [r["Id"] for r in records] == ["a1", "a2", "a3"]
        finally:
            client_mod.requests.request = original

    def test_max_records_caps_the_walk(self, mock_api, config, monkeypatch):
        monkeypatch.setattr(client_module, "MAX_PAGE_ROUNDS", 50)
        client = GuardianClient(config)
        records = client.paginate("/aidr/queries/agents/v1", {"limit": 1}, max_records=1)
        assert len(records) == 1

    def test_pagination_survives_a_synthesized_total(self, mock_api, config):
        # meta.pagination.total only tells the truth on a short page; the walk
        # must go by page length, not total.
        client = GuardianClient(config)
        records = client.paginate("/aidr/queries/tools/v1", {"limit": 50})
        assert len(records) == 1  # one tool in the default fixture


class TestAggregate:
    def test_full_500_group_page_is_flagged(self, mock_api, config):
        mock_api.route(
            "GET", "/aidr/aggregates/tools/v1", resources=[{"Name": f"t{i}", "count": 1} for i in range(500)]
        )
        client = GuardianClient(config)
        notices = []
        client.aggregate("/aidr/aggregates/tools/v1", {}, notices=notices)
        assert any("500" in n for n in notices)

    def test_short_aggregate_is_not_flagged(self, mock_api, config):
        client = GuardianClient(config)
        notices = []
        client.aggregate("/aidr/aggregates/tools/v1", {}, notices=notices)
        assert not notices
