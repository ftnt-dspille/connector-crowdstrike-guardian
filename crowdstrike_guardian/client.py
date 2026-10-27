"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""
import threading
import time
from urllib.parse import urlparse

import requests
from connectors.core.connector import ConnectorError, get_logger

from .constants import (
    AGGREGATE_GROUP_LIMIT,
    DEFAULT_TIMEOUT,
    MAX_ATTEMPTS,
    MAX_LIMIT,
    MAX_OFFSET,
    MAX_PAGE_ROUNDS,
    MAX_RETRY_WAIT,
    TOKEN_EXPIRY_SKEW_SECONDS,
    TOKEN_PATH,
    WINDOW_LADDER,
)

logger = get_logger('crowdstrike_guardian')

# Token minting is the expensive step (one round trip per call otherwise), so
# live tokens are shared per (base_url, client_id) across worker processes.
_TOKENS = {}
_TOKEN_LOCK = threading.Lock()


def normalize_base_url(config):
    """Resolve the API base URL from the cloud dropdown or the custom field.

    CrowdStrike's clouds differ only in host; the /aidr paths are the same.
    A base_url entered directly wins over the dropdown so pointed-at
    deployments (or a proxy) keep working after an upgrade.
    """
    base = (config.get('base_url') or '').strip()
    if base:
        if not base.startswith(('http://', 'https://')):
            base = 'https://' + base
        return base.rstrip('/')
    cloud = (config.get('cloud') or '').strip() or 'https://api.crowdstrike.com'
    if cloud == 'custom':
        raise ConnectorError('Cloud is set to Custom: fill in the Base URL field, '
                             'for example https://api.crowdstrike.com')
    return cloud.rstrip('/')


def error_details(response):
    """Pull a human-readable message out of a Falcon error envelope."""
    try:
        body = response.json()
    except ValueError:
        return (response.text or '').strip()[:500]
    if not isinstance(body, dict):
        return str(body)[:500]
    parts = []
    for err in body.get('errors') or []:
        if isinstance(err, dict) and err.get('message'):
            parts.append('%s: %s' % (err.get('code', ''), err['message'])
                         if err.get('code') else str(err['message']))
    if parts:
        return '; '.join(parts)
    return body.get('detail', '')[:500] or str(body)[:500]


def _hint(status, details):
    lowered = details.lower()
    if status == 401:
        if 'token' in lowered or 'expired' in lowered:
            return 'The access token was rejected. Re-run the operation; the connector mints a fresh one.'
        return ('Check the Client ID and Client Secret, and that they belong to the '
                'selected cloud (a US-2 client cannot authenticate against US-1).')
    if status == 403:
        if 'scope' in lowered or 'aidr' in lowered or 'flag' in lowered:
            return ('The API client lacks the AIDR: READ scope, or the Guardian API is not '
                    'enabled for this CID. Grant the scope in Falcon: Support and resources '
                    '> API clients and keys.')
        return 'The API client is authenticated but not allowed to call this endpoint.'
    if status == 400:
        if 'time_range' in lowered:
            return 'Narrow the Time Range (LogScale-backed routes accept at most 7d).'
        return 'Read the message: it names the parameter the API refused.'
    if status == 404:
        return 'The endpoint or the requested id does not exist on this cloud.'
    if status == 504:
        return ('The query was too broad for the API to finish. Narrow the Time Range or '
                'add a filter (aid, product, session id).')
    return ''


def _sleep(seconds):
    time.sleep(seconds)


class GuardianClient(object):
    """Thin REST client for the Falcon Guardian (AIDR) API.

    Every call goes through request(): token minting and refresh, retries,
    error reporting and pagination live here. All /aidr operations are GETs;
    the only POST is the token mint.
    """

    def __init__(self, config):
        config = config or {}
        self.base_url = normalize_base_url(config)
        self.client_id = (config.get('client_id') or '').strip()
        self.client_secret = config.get('client_secret') or ''
        self.verify = config.get('verify_ssl', True)
        self.timeout = self._timeout(config.get('timeout'))
        self._token = None

    @staticmethod
    def _timeout(value):
        try:
            value = int(value)
        except (TypeError, ValueError):
            return DEFAULT_TIMEOUT
        return value if value > 0 else DEFAULT_TIMEOUT

    # -- auth --------------------------------------------------------------

    def _mint_token(self):
        """Client-credentials grant. CrowdStrike answers 201 with expires_in."""
        url = self.base_url + TOKEN_PATH
        try:
            response = requests.request(
                'POST', url,
                data={'client_id': self.client_id,
                      'client_secret': self.client_secret,
                      'grant_type': 'client_credentials'},
                headers={'Accept': 'application/json'},
                verify=self.verify, timeout=self.timeout)
        except requests.exceptions.SSLError as err:
            raise ConnectorError('SSL certificate validation failed for %s: %s' % (url, err))
        except requests.exceptions.Timeout:
            raise ConnectorError('The token request to %s timed out after %ss.' % (url, self.timeout))
        except requests.exceptions.ConnectionError as err:
            raise ConnectorError('Could not connect to %s: %s' % (url, err))
        if response.status_code not in (200, 201):
            details = error_details(response)
            hint = _hint(response.status_code, details)
            message = 'Token request failed (HTTP %s): %s' % (response.status_code, details or response.reason)
            if hint:
                message += ' Hint: ' + hint
            raise ConnectorError(message)
        try:
            body = response.json()
        except ValueError:
            raise ConnectorError('Token endpoint returned a non-JSON body.')
        token = body.get('access_token')
        if not token:
            raise ConnectorError('Token endpoint did not return an access_token.')
        try:
            lifetime = int(body.get('expires_in') or 1800)
        except (TypeError, ValueError):
            lifetime = 1800
        return token, time.time() + max(lifetime - TOKEN_EXPIRY_SKEW_SECONDS, 30)

    def _auth_header(self):
        """Bearer token, minted once and shared until close to expiry."""
        if not self.client_id or not self.client_secret:
            raise ConnectorError('Client ID and Client Secret are required. '
                                 'Create an API client in the Falcon console with the AIDR: READ scope.')
        key = (self.base_url, self.client_id)
        with _TOKEN_LOCK:
            token, expires = _TOKENS.get(key, (None, 0))
            if token and time.time() < expires:
                return {'Authorization': 'Bearer %s' % token}
            token, expires = self._mint_token()
            _TOKENS[key] = (token, expires)
            return {'Authorization': 'Bearer %s' % token}

    def invalidate_token(self):
        """Drop the cached token so the next call mints a fresh one."""
        with _TOKEN_LOCK:
            _TOKENS.pop((self.base_url, self.client_id), None)
            self._token = None

    # -- request -----------------------------------------------------------

    def request(self, method, path, params=None):
        """Call the API and return the decoded envelope (meta/resources/errors).

        Non-2xx replies raise ConnectorError carrying the API's own message.
        Retries: 429 (Retry-After), then 502/503/504 once more for GETs.
        A 401 re-mints the token once before giving up.
        """
        if not path.startswith('/'):
            path = '/' + path
        url = self.base_url + path
        if params:
            params = {k: v for k, v in params.items() if v is not None and v != ''}
        method = method.upper()

        attempt = 0
        reminted = False
        while True:
            attempt += 1
            headers = {'Accept': 'application/json'}
            headers.update(self._auth_header())
            logger.info('%s %s', method, url)
            try:
                response = requests.request(method, url, params=params or None,
                                            headers=headers, verify=self.verify,
                                            timeout=self.timeout)
            except requests.exceptions.SSLError as err:
                raise ConnectorError('SSL certificate validation failed for %s: %s' % (url, err))
            except requests.exceptions.Timeout:
                raise ConnectorError('The request to %s timed out after %ss.' % (url, self.timeout))
            except requests.exceptions.ConnectionError as err:
                raise ConnectorError('Could not connect to %s: %s' % (url, err))

            if response.status_code == 401 and not reminted:
                reminted = True
                self.invalidate_token()
                continue
            if response.status_code == 429 and attempt < MAX_ATTEMPTS:
                _sleep(self._retry_wait(response, attempt))
                continue
            if response.status_code in (502, 503) and method == 'GET' and attempt < MAX_ATTEMPTS:
                _sleep(min(2 ** attempt, MAX_RETRY_WAIT))
                continue
            break

        if not response.ok:
            details = error_details(response)
            hint = _hint(response.status_code, details)
            message = 'HTTP %s %s %s: %s' % (response.status_code, method, path, details or response.reason)
            if hint:
                message += ' Hint: ' + hint
            raise ConnectorError(message)
        if response.status_code == 204 or not response.content:
            return {'resources': [], 'errors': [], 'meta': None}
        try:
            return response.json()
        except ValueError:
            raise ConnectorError('Guardian returned a non-JSON body for %s.' % path)

    @staticmethod
    def _retry_wait(response, attempt):
        try:
            wait = float(response.headers.get('Retry-After'))
        except (TypeError, ValueError):
            wait = 2 ** attempt
        return max(0.0, min(wait, MAX_RETRY_WAIT))

    # -- window ladder -----------------------------------------------------

    @staticmethod
    def _window_hours(value):
        """'90d' -> 2160. None/invalid -> None (no ceiling known)."""
        text = str(value or '').strip().lower()
        for suffix, factor in (('m', 1.0 / 60), ('h', 1.0), ('d', 24.0)):
            if text.endswith(suffix):
                try:
                    return float(text[:-1]) * factor
                except ValueError:
                    return None
        try:
            return float(text)  # bare seconds
        except ValueError:
            return None

    def _narrow(self, current):
        """The next narrower preset window, or None when already at the floor."""
        hours = self._window_hours(current)
        ladder = [(self._window_hours(w), w) for w in WINDOW_LADDER]
        ladder.sort(reverse=True)
        for rung_hours, rung in ladder:
            if hours is None or rung_hours < hours:
                return rung
        return None

    def query(self, route, params=None, notices=None):
        """GET a queries/* or aggregates/* route, narrowing the window if the
        API refuses it (504 timeout, or a 400 naming time_range).

        `notices`, when given a list, collects what was narrowed so the
        operation result can carry it. Entities routes reject time_range
        outright and are sent as-is.
        """
        route_params = dict(params or {})
        tried = {route_params.get('time_range') or ''}
        while True:
            try:
                return self.request('GET', route, route_params)
            except ConnectorError as err:
                # Refusal looks like a 504, or a 400 whose message names
                # time_range. Anything else is not worth a retry.
                text = str(err)
                current = route_params.get('time_range')
                if 'time_range' not in text and '504' not in text:
                    raise
                narrower = self._narrow(current)
                if not narrower or narrower in tried:
                    raise
                tried.add(narrower)
                logger.warning('%s refused time_range=%s; retrying with %s', route, current, narrower)
                if notices is not None:
                    notices.append('Time range %s was refused; retried with %s.' % (current, narrower))
                route_params = dict(route_params, time_range=narrower)

    # -- pagination --------------------------------------------------------

    def paginate(self, route, params=None, max_records=None, notices=None):
        """Walk offset/limit pages until a short page comes back.

        meta.pagination.total only tells the truth on a short page (the API
        synthesizes it as offset + len(page), so on a full page it merely
        restates the cursor) -- page length is the reliable end signal.
        """
        params = dict(params or {})
        limit = int(params.get('limit') or 50)
        params['limit'] = limit
        offset = int(params.get('offset') or 0)
        items = []
        rounds = 0
        while True:
            rounds += 1
            if rounds > MAX_PAGE_ROUNDS:
                if notices is not None:
                    notices.append('Stopped after %d pages.' % MAX_PAGE_ROUNDS)
                break
            page = self.query(route, dict(params, offset=offset), notices=notices)
            batch = page.get('resources') or []
            items.extend(batch)
            if max_records and len(items) >= max_records:
                return items[:max_records]
            if len(batch) < limit or offset + len(batch) > MAX_OFFSET or not batch:
                return items
            offset += len(batch)
        return items

    def aggregate(self, route, params=None, notices=None):
        """GET an aggregates route and flag the silent 500-group truncation."""
        page = self.query(route, params, notices=notices)
        resources = page.get('resources') or []
        if len(resources) >= AGGREGATE_GROUP_LIMIT and notices is not None:
            notices.append('The aggregate returned 500 groups, the server-side maximum; '
                           'results are likely truncated. Narrow with aid, product or time_range.')
        return page
