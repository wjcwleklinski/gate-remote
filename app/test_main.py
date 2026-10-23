"""Tests for the parts that fail silently if they are wrong.

Token checks and rate limiting can't be verified by watching the gate: a
mistake there still opens it, just for the wrong person or too often.
"""

from __future__ import annotations

import json
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from main import Config, Throttle, collect_roles, create_app

ISSUER = "https://keycloak.example.com/realms/homelab"
AUDIENCE = "gate-remote-api"
CERTS_URL = f"{ISSUER}/protocol/openid-connect/certs"


def _make_key(kid: str):
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(private.public_key()))
    jwk |= {"kid": kid, "use": "sig", "alg": "RS256"}
    return private, jwk


SIGNING_KEY, SIGNING_JWK = _make_key("test-key-1")
FOREIGN_KEY, _ = _make_key("test-key-1")  # same kid, different key material


def make_token(private_key=SIGNING_KEY, *, kid="test-key-1", **overrides) -> str:
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "1c8f0e4a-0000-0000-0000-000000000001",
        "preferred_username": "wjc",
        "iat": now,
        "exp": now + 300,
        "realm_access": {"roles": ["RESIDENT", "default-roles-homelab"]},
    }
    claims.update(overrides)
    return jwt.encode(claims, private_key, algorithm="RS256", headers={"kid": kid})


class FakeRelay:
    """Stands in for the GPIO pin — records pulses instead of driving one."""

    def __init__(self):
        self.pulses = 0

    async def pulse(self):
        self.pulses += 1

    def close(self):
        pass


def _handler(request: httpx.Request) -> httpx.Response:
    if request.url.path.endswith("/.well-known/openid-configuration"):
        return httpx.Response(200, json={"issuer": ISSUER, "jwks_uri": CERTS_URL})
    if request.url.path.endswith("/protocol/openid-connect/certs"):
        return httpx.Response(200, json={"keys": [SIGNING_JWK]})
    return httpx.Response(404)


@pytest.fixture
def relay():
    return FakeRelay()


@pytest.fixture
def client(tmp_path, relay):
    config = Config(
        issuer=ISSUER,
        audience=AUDIENCE,
        required_role="RESIDENT",
        gpio_mock=True,
        min_interval_seconds=0.0,
        max_per_window=100,
        jwks_cache=tmp_path / "jwks.json",
    )
    app = create_app(
        config,
        relay=relay,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )
    with TestClient(app) as test_client:
        yield test_client


def _open(client, token: str | None):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    return client.post("/trigger", headers=headers)


# ── Authentication ───────────────────────────────────────────────────────────


def test_valid_token_opens_the_gate(client, relay):
    response = _open(client, make_token())
    assert response.status_code == 202
    assert response.json()["status"] == "triggered"
    assert relay.pulses == 1


def test_missing_token_is_rejected(client, relay):
    assert _open(client, None).status_code == 401
    assert relay.pulses == 0


def test_garbage_token_is_rejected(client, relay):
    assert _open(client, "not-a-jwt").status_code == 401
    assert relay.pulses == 0


def test_token_signed_by_unknown_key_is_rejected(client, relay):
    """Correct kid, correct claims, wrong signing key."""
    assert _open(client, make_token(FOREIGN_KEY)).status_code == 401
    assert relay.pulses == 0


def test_expired_token_is_rejected(client, relay):
    now = int(time.time())
    token = make_token(iat=now - 7200, exp=now - 3600)
    assert _open(client, token).status_code == 401
    assert relay.pulses == 0


def test_wrong_audience_is_rejected(client, relay):
    assert _open(client, make_token(aud="some-other-client")).status_code == 401
    assert relay.pulses == 0


def test_wrong_issuer_is_rejected(client, relay):
    token = make_token(iss="https://keycloak.example.com/realms/other")
    assert _open(client, token).status_code == 401
    assert relay.pulses == 0


def test_unsigned_token_is_rejected(client, relay):
    """alg=none must never be accepted."""
    token = jwt.encode({"iss": ISSUER, "aud": AUDIENCE, "sub": "x"}, key=None, algorithm="none")
    assert _open(client, token).status_code == 401
    assert relay.pulses == 0


# ── Authorisation ────────────────────────────────────────────────────────────


def test_token_without_required_role_is_forbidden(client, relay):
    token = make_token(realm_access={"roles": ["default-roles-homelab"]})
    response = _open(client, token)
    assert response.status_code == 403
    assert relay.pulses == 0


def test_client_role_is_accepted(client, relay):
    """A role granted through resource_access rather than realm_access."""
    token = make_token(
        realm_access={"roles": []},
        resource_access={"gate-remote-api": {"roles": ["RESIDENT"]}},
    )
    assert _open(client, token).status_code == 202
    assert relay.pulses == 1


def test_collect_roles_qualifies_client_roles():
    roles = collect_roles(
        {
            "realm_access": {"roles": ["RESIDENT"]},
            "resource_access": {"gate-remote-api": {"roles": ["gate.open"]}},
        }
    )
    assert roles == {"RESIDENT", "gate.open", "gate-remote-api:gate.open"}


def test_collect_roles_tolerates_malformed_claims():
    assert collect_roles({"realm_access": "nonsense", "resource_access": ["also nonsense"]}) == set()


# ── Throttling ───────────────────────────────────────────────────────────────


def test_throttle_enforces_minimum_interval():
    throttle = Throttle(Config(min_interval_seconds=3.0, max_per_window=10, window_seconds=60))
    throttle.record(now=100.0)
    assert throttle.retry_after(now=101.0) == pytest.approx(2.0)
    assert throttle.retry_after(now=103.5) == 0.0


def test_throttle_enforces_window_cap():
    throttle = Throttle(Config(min_interval_seconds=0.0, max_per_window=3, window_seconds=60))
    for offset in range(3):
        throttle.record(now=100.0 + offset)
    assert throttle.retry_after(now=105.0) > 0
    # Once the first event ages out of the window there is room again.
    assert throttle.retry_after(now=161.0) == 0.0


def test_rapid_second_request_is_throttled(tmp_path, relay):
    config = Config(
        issuer=ISSUER,
        audience=AUDIENCE,
        gpio_mock=True,
        min_interval_seconds=30.0,
        jwks_cache=tmp_path / "jwks.json",
    )
    app = create_app(
        config,
        relay=relay,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )
    with TestClient(app) as client:
        token = make_token()
        assert _open(client, token).status_code == 202
        response = _open(client, token)
        assert response.status_code == 429
        assert int(response.headers["Retry-After"]) > 0
    assert relay.pulses == 1


# ── Offline operation ────────────────────────────────────────────────────────


def test_keys_are_cached_to_disk_for_wan_outages(tmp_path, relay):
    cache = tmp_path / "jwks.json"
    config = Config(issuer=ISSUER, audience=AUDIENCE, gpio_mock=True, jwks_cache=cache)

    app = create_app(
        config,
        relay=relay,
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(_handler)),
    )
    with TestClient(app) as client:
        assert _open(client, make_token()).status_code == 202
    assert json.loads(cache.read_text())["keys"][0]["kid"] == "test-key-1"

    # Keycloak now unreachable: the cached keys must still validate tokens.
    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("network is unreachable")

    offline = create_app(
        config,
        relay=FakeRelay(),
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(unreachable)),
    )
    with TestClient(offline) as client:
        assert _open(client, make_token()).status_code == 202


def test_healthz_needs_no_token(client):
    assert client.get("/healthz").status_code == 200
