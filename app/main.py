#!/usr/bin/env python3
"""Gate Remote — presses a sacrificed radio remote via a GPIO pin.

POST /trigger with a Keycloak access token that carries the RESIDENT role and
the pin wired to the remote's button pad goes HIGH for PULSE_SECONDS.

Successor to the gate-server prototype. RPi.GPIO does not work on the Pi 5
(the RP1 chip needs the gpiochip character device, reached here through
gpiozero's lgpio backend), and signing keys are now refreshed on rotation and
cached to disk instead of fetched once and held in memory forever.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from math import ceil
from pathlib import Path
from typing import Any

import httpx
import jwt
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jwt import PyJWK

ALGORITHMS = ["RS256"]

log = logging.getLogger("gate-remote")


def audit(event: str, **fields: Any) -> None:
    """One JSON line per security-relevant event, straight to journald."""
    log.info(json.dumps({"event": event, **fields}, default=str))


# ── Configuration ────────────────────────────────────────────────────────────


def _env_bool(name: str, default: bool) -> bool:
    return os.environ.get(name, str(default)).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Config:
    # Empty issuer is allowed so the module always imports; it is rejected at
    # startup instead, where the error message can actually be read.
    issuer: str = ""
    audience: str = "gate-remote-api"
    required_role: str = "RESIDENT"

    gpio_pin: int = 17
    pulse_seconds: float = 0.5
    gpio_active_high: bool = True
    gpio_mock: bool = False

    # The endpoint drives a physical actuator, so it is capped far below
    # anything a human needs. Counters are per-process — run a single worker.
    min_interval_seconds: float = 3.0
    max_per_window: int = 6
    window_seconds: float = 60.0

    # Keycloak sits behind Cloudflare, so a WAN outage would otherwise leave
    # the Pi unable to verify a perfectly good token — exactly when you are
    # standing in front of a closed gate. Keys are kept on disk for that case.
    jwks_cache: Path = Path("/var/lib/gate-remote/jwks.json")
    jwks_min_refresh_seconds: float = 60.0
    clock_leeway_seconds: int = 30
    http_timeout_seconds: float = 10.0

    @classmethod
    def from_env(cls) -> Config:
        return cls(
            issuer=os.environ.get("KEYCLOAK_ISSUER", "").rstrip("/"),
            audience=os.environ.get("KEYCLOAK_AUDIENCE", "gate-remote-api"),
            required_role=os.environ.get("REQUIRED_ROLE", "RESIDENT"),
            gpio_pin=int(os.environ.get("GPIO_PIN", "17")),
            pulse_seconds=float(os.environ.get("PULSE_SECONDS", "0.5")),
            gpio_active_high=_env_bool("GPIO_ACTIVE_HIGH", True),
            gpio_mock=_env_bool("GPIO_MOCK", False),
            min_interval_seconds=float(os.environ.get("MIN_INTERVAL_SECONDS", "3")),
            max_per_window=int(os.environ.get("MAX_PER_WINDOW", "6")),
            window_seconds=float(os.environ.get("WINDOW_SECONDS", "60")),
            jwks_cache=Path(os.environ.get("JWKS_CACHE", "/var/lib/gate-remote/jwks.json")),
        )

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"


# ── Token validation ─────────────────────────────────────────────────────────


class AuthError(Exception):
    def __init__(self, reason: str, status_code: int = status.HTTP_401_UNAUTHORIZED):
        super().__init__(reason)
        self.reason = reason
        self.status_code = status_code


@dataclass(frozen=True)
class Principal:
    subject: str
    username: str
    roles: frozenset[str] = field(default_factory=frozenset)


class Jwks:
    """Realm signing keys, cached in memory and mirrored to disk."""

    def __init__(self, config: Config, client: httpx.AsyncClient):
        self._config = config
        self._client = client
        self._keys: dict[str, Any] = {}
        self._jwks_uri: str | None = None
        self._lock = asyncio.Lock()
        self._last_fetch = 0.0

    def _ingest(self, document: dict) -> int:
        keys: dict[str, Any] = {}
        for entry in document.get("keys", []):
            # Keycloak publishes encryption keys alongside signing keys.
            if entry.get("use") == "enc" or not entry.get("kid"):
                continue
            try:
                keys[entry["kid"]] = PyJWK.from_dict(entry).key
            except Exception:  # noqa: BLE001 - key types this build cannot load
                log.debug("skipping unusable JWKS entry kid=%s", entry.get("kid"))
        # An empty result means the fetch was useless; keep what we had.
        if keys:
            self._keys = keys
        return len(keys)

    def load_cached(self) -> int:
        try:
            document = json.loads(self._config.jwks_cache.read_text())
        except (OSError, ValueError):
            return 0
        count = self._ingest(document)
        if count:
            log.info("loaded %d signing key(s) from %s", count, self._config.jwks_cache)
        return count

    def _write_cache(self, document: dict) -> None:
        path = self._config.jwks_cache
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(json.dumps(document))
            tmp.chmod(0o600)
            tmp.replace(path)
        except OSError as exc:
            # Not fatal: the in-memory copy still works until the next restart.
            log.warning("could not write JWKS cache %s: %s", path, exc)

    async def _discover(self) -> str:
        if self._jwks_uri:
            return self._jwks_uri
        response = await self._client.get(self._config.discovery_url)
        response.raise_for_status()
        document = response.json()
        advertised = str(document.get("issuer", "")).rstrip("/")
        if advertised != self._config.issuer:
            raise AuthError(
                f"discovery document advertises issuer {advertised!r}, "
                f"expected {self._config.issuer!r}"
            )
        self._jwks_uri = document["jwks_uri"]
        return self._jwks_uri

    async def refresh(self, *, force: bool = False) -> None:
        async with self._lock:
            now = time.monotonic()
            # Without a floor, a stream of tokens bearing an unknown kid turns
            # into a stream of requests to Keycloak.
            if not force and now - self._last_fetch < self._config.jwks_min_refresh_seconds:
                return
            self._last_fetch = now
            response = await self._client.get(await self._discover())
            response.raise_for_status()
            document = response.json()
            if self._ingest(document):
                self._write_cache(document)

    async def key_for(self, kid: str) -> Any:
        key = self._keys.get(kid)
        if key is not None:
            return key
        # Unknown kid usually means Keycloak rotated its keys.
        try:
            await self.refresh()
        except (httpx.HTTPError, KeyError) as exc:
            log.warning("JWKS refresh failed: %s", exc)
        key = self._keys.get(kid)
        if key is None:
            raise AuthError("token signed by an unknown key")
        return key


def collect_roles(claims: dict) -> frozenset[str]:
    """Realm and client roles, flattened.

    Client roles are recorded twice — bare (`RESIDENT`) and qualified
    (`gate-remote-api:RESIDENT`) — so REQUIRED_ROLE can be written either way.
    The qualified form is the stricter one: it will not match a same-named
    role that happens to be defined on some other client.
    """
    roles: set[str] = set()
    realm_access = claims.get("realm_access")
    if isinstance(realm_access, dict):
        roles.update(str(r) for r in realm_access.get("roles", []))

    resource_access = claims.get("resource_access")
    if isinstance(resource_access, dict):
        for client, access in resource_access.items():
            if not isinstance(access, dict):
                continue
            for role in access.get("roles", []):
                roles.add(str(role))
                roles.add(f"{client}:{role}")
    return frozenset(roles)


class Verifier:
    def __init__(self, config: Config, jwks: Jwks):
        self._config = config
        self._jwks = jwks

    async def verify(self, token: str) -> Principal:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise AuthError("malformed token") from None

        if header.get("alg") not in ALGORITHMS:
            raise AuthError(f"unsupported signing algorithm {header.get('alg')!r}")
        kid = header.get("kid")
        if not kid:
            raise AuthError("token carries no key id")

        key = await self._jwks.key_for(kid)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=ALGORITHMS,
                audience=self._config.audience,
                issuer=self._config.issuer,
                leeway=self._config.clock_leeway_seconds,
                options={"require": ["exp", "iat", "iss", "aud", "sub"]},
            )
        except jwt.ExpiredSignatureError:
            raise AuthError("token expired") from None
        except jwt.InvalidAudienceError:
            raise AuthError(f"token audience does not include {self._config.audience!r}") from None
        except jwt.InvalidIssuerError:
            raise AuthError("token was issued by a different realm") from None
        except jwt.PyJWTError as exc:
            raise AuthError(f"token rejected: {exc}") from None

        roles = collect_roles(claims)
        if self._config.required_role not in roles:
            raise AuthError(
                f"token lacks the {self._config.required_role!r} role",
                status.HTTP_403_FORBIDDEN,
            )
        return Principal(
            subject=str(claims["sub"]),
            username=str(claims.get("preferred_username", claims["sub"])),
            roles=roles,
        )


# ── Throttling ───────────────────────────────────────────────────────────────


class Throttle:
    def __init__(self, config: Config):
        self._min_interval = config.min_interval_seconds
        self._max_per_window = config.max_per_window
        self._window = config.window_seconds
        self._events: deque[float] = deque()

    def retry_after(self, now: float | None = None) -> float:
        """Seconds to wait, or 0.0 if the gate may be triggered right now."""
        now = time.monotonic() if now is None else now
        while self._events and now - self._events[0] > self._window:
            self._events.popleft()

        if self._events:
            since_last = now - self._events[-1]
            if since_last < self._min_interval:
                return self._min_interval - since_last
        if len(self._events) >= self._max_per_window:
            return self._window - (now - self._events[0])
        return 0.0

    def record(self, now: float | None = None) -> None:
        self._events.append(time.monotonic() if now is None else now)


# ── Hardware ─────────────────────────────────────────────────────────────────


class Relay:
    """The GPIO pin bridged onto the remote's button pad."""

    def __init__(self, config: Config):
        self.pin = config.gpio_pin
        self.pulse_seconds = config.pulse_seconds
        self._device = None
        if not config.gpio_mock:
            from gpiozero import DigitalOutputDevice

            # initial_value=False leaves the pin inactive, so neither a reboot
            # nor a service restart ever opens the gate on its own.
            self._device = DigitalOutputDevice(
                self.pin,
                active_high=config.gpio_active_high,
                initial_value=False,
            )

    async def pulse(self) -> None:
        if self._device is None:
            log.warning("MOCK: would hold pin %s for %.2fs", self.pin, self.pulse_seconds)
            await asyncio.sleep(self.pulse_seconds)
            return
        self._device.on()
        try:
            await asyncio.sleep(self.pulse_seconds)
        finally:
            self._device.off()

    def close(self) -> None:
        if self._device is not None:
            self._device.close()


# ── Application ──────────────────────────────────────────────────────────────

bearer = HTTPBearer(auto_error=False)


async def authenticate(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
) -> Principal:
    if credentials is None:
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            detail="missing bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        return await request.app.state.verifier.verify(credentials.credentials)
    except AuthError as exc:
        audit(
            "auth_denied",
            reason=exc.reason,
            client=request.client.host if request.client else None,
        )
        headers = (
            {"WWW-Authenticate": f'Bearer error="invalid_token", error_description="{exc.reason}"'}
            if exc.status_code == status.HTTP_401_UNAUTHORIZED
            else None
        )
        raise HTTPException(exc.status_code, detail=exc.reason, headers=headers) from None


def create_app(
    config: Config | None = None,
    *,
    relay: Relay | None = None,
    http_client: httpx.AsyncClient | None = None,
) -> FastAPI:
    """Build the app. `relay` and `http_client` exist so tests can inject."""
    config = config or Config.from_env()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if not config.issuer:
            raise RuntimeError(
                "KEYCLOAK_ISSUER is not set — expected something like "
                "https://keycloak.example.com/realms/homelab"
            )
        client = http_client or httpx.AsyncClient(timeout=config.http_timeout_seconds)
        jwks = Jwks(config, client)
        jwks.load_cached()
        try:
            await jwks.refresh(force=True)
        except (httpx.HTTPError, AuthError, KeyError) as exc:
            # Starting offline is fine as long as the disk cache has keys.
            log.warning("could not reach Keycloak at startup: %s", exc)

        app.state.config = config
        app.state.verifier = Verifier(config, jwks)
        app.state.relay = relay or Relay(config)
        app.state.throttle = Throttle(config)
        app.state.lock = asyncio.Lock()

        audit(
            "started",
            issuer=config.issuer,
            audience=config.audience,
            required_role=config.required_role,
            gpio_pin=config.gpio_pin,
            gpio_mock=config.gpio_mock,
        )
        try:
            yield
        finally:
            app.state.relay.close()
            if http_client is None:
                await client.aclose()

    app = FastAPI(title="Gate Remote", version="0.1.0", lifespan=lifespan)

    @app.get("/healthz")
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    @app.post("/trigger", status_code=status.HTTP_202_ACCEPTED)
    async def trigger(request: Request, principal: Principal = Depends(authenticate)) -> dict:
        state = request.app.state
        # One lock over check-pulse-record: the whole point is that two
        # requests can never interleave into a double press.
        async with state.lock:
            wait = state.throttle.retry_after()
            if wait > 0:
                audit("throttled", user=principal.username, retry_after=round(wait, 2))
                raise HTTPException(
                    status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="gate was triggered too recently",
                    headers={"Retry-After": str(max(1, ceil(wait)))},
                )
            await state.relay.pulse()
            state.throttle.record()

        audit("gate_opened", user=principal.username, subject=principal.subject)
        return {
            "status": "triggered",
            "pulse_seconds": state.config.pulse_seconds,
            "user": principal.username,
        }

    return app


def configure_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


configure_logging()
app = create_app()
