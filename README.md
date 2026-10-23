# gate-remote

Opens the driveway gate with an HTTP request. A radio remote is wired to a
Raspberry Pi 5 GPIO pin; an authenticated `POST /trigger` holds that pin HIGH
for half a second, which is the same as pressing the remote's button.

```
phone ──HTTPS──► Cloudflare ──tunnel──► nginx-ingress ──HTTP──► Pi :8080 ──GPIO 17──► remote ──radio──► gate
                                                                   │
                                          signing keys (JWKS) ◄────┘ from Keycloak
```

## Layout

| Path | Runs on | What it is |
|---|---|---|
| `app/main.py` | Pi | The whole service — config, token checks, rate limit, GPIO, HTTP |
| `app/test_main.py` | laptop | Tests for auth, roles, throttling and offline operation |
| `app/.env.example` | Pi | Every setting, commented. Becomes `/etc/gate-remote/gate-remote.env` |
| `app/gate-remote.service` | Pi | systemd unit: start at boot, restart on crash |
| `app/install.sh` | laptop | Copies the app to the Pi and (re)starts it |
| `k8s/gate-ingress.yaml` | cluster | Routes `gate.wleklinski.org` to the Pi |

## How a request is handled

1. **Bearer token present?** No → `401`.
2. **Token header checked.** Algorithm must be `RS256` and a key id (`kid`)
   must be present. `alg: none` and HMAC tricks are refused here.
3. **Signing key looked up by `kid`.** Keys come from Keycloak's JWKS endpoint
   and are kept in memory and on disk. An unknown `kid` triggers one refetch
   (at most once a minute) to pick up a key rotation.
4. **Signature and claims verified.** `iss` must equal `KEYCLOAK_ISSUER`, `aud`
   must contain `KEYCLOAK_AUDIENCE`, the token must not be expired (30s clock
   leeway). Any failure → `401`.
5. **Role checked.** The token must carry `REQUIRED_ROLE` (default
   `RESIDENT`) as a realm or client role. Missing → `403`.
6. **Rate limit checked**, under a lock so two requests can never overlap into
   a double press: at least 3s since the last open and at most 6 per minute.
   Exceeded → `429` with `Retry-After`.
7. **Pin pulsed.** HIGH for `PULSE_SECONDS`, then LOW — the LOW is in a
   `finally`, so the pin is released even if something goes wrong mid-pulse.
8. **Audit line written** and `202` returned.

Every denial, throttle and open is logged as one JSON line to journald:

```
{"event": "gate_opened", "user": "wjc", "subject": "1c8f…"}
{"event": "auth_denied", "reason": "token expired", "client": "192.168.0.11"}
```

### Working without internet

Keycloak is reached through Cloudflare, so if the WAN drops the Pi cannot
fetch keys. To keep the gate usable, fetched keys are written to
`/var/lib/gate-remote/jwks.json` and loaded at startup. As long as the phone
has a token that has not expired yet, the gate opens even with Keycloak
unreachable — over the LAN, since the public route needs the internet too.

### Safe by default

- The pin starts LOW (`initial_value=False`), so a reboot or a service restart
  never opens the gate.
- Only `/trigger` and `/healthz` are routed from the internet. FastAPI's
  `/docs` and `/openapi.json` are reachable on the LAN only.
- The service holds no secrets. It only verifies tokens Keycloak signed.

## Hardware

- Raspberry Pi 5. **`RPi.GPIO` does not work on it** — the RP1 chip is driven
  through gpiozero's lgpio backend (`GPIOZERO_PIN_FACTORY=lgpio`).
- Remote's button pad wired to **BCM 17 (physical pin 11)** with a common
  ground. Pressed by driving the pin HIGH.
- If the gate does not react, raise `PULSE_SECONDS` (the prototype used `1.0`).
  If the logic is inverted, set `GPIO_ACTIVE_HIGH=false`.

## Configuration

Read from environment variables — `/etc/gate-remote/gate-remote.env` on the Pi.
See `app/.env.example` for the full commented list.

| Variable | Default | |
|---|---|---|
| `KEYCLOAK_ISSUER` | *(required)* | `https://<keycloak-host>/realms/<realm>` — must match the token's `iss` exactly |
| `KEYCLOAK_AUDIENCE` | `gate-remote-api` | Needs an audience mapper in Keycloak, or every request is `401` |
| `REQUIRED_ROLE` | `RESIDENT` | `ROLE` or `client:ROLE` |
| `GPIO_PIN` | `17` | BCM numbering |
| `PULSE_SECONDS` | `0.5` | Length of the button press |
| `GPIO_ACTIVE_HIGH` | `true` | |
| `GPIO_MOCK` | `false` | Log the pulse instead of touching hardware |
| `MIN_INTERVAL_SECONDS` | `3` | |
| `MAX_PER_WINDOW` / `WINDOW_SECONDS` | `6` / `60` | |
| `JWKS_CACHE` | `/var/lib/gate-remote/jwks.json` | |
| `LOG_LEVEL` | `INFO` | |

## Running the tests

```bash
cd app
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt pytest cryptography
.venv/bin/pytest -q
```

The tests mint their own tokens with a throwaway RSA key and fake Keycloak's
HTTP endpoints, so they need neither Keycloak nor a Pi.

## Running on a laptop

```bash
cd app
KEYCLOAK_ISSUER=https://keycloak.example.com/realms/homelab GPIO_MOCK=true \
  .venv/bin/uvicorn main:app --port 8080
```

With `GPIO_MOCK=true` a successful request logs `MOCK: would hold pin 17`
instead of pulsing.

## Deploying to the Pi

Prerequisites: Raspberry Pi OS on the Pi 5, SSH access, and a **static IP**
(the cluster addresses the Pi by IP — a hostname will not work).

```bash
PI_HOST=pi@192.168.0.20 bash app/install.sh
```

The script installs `python3-gpiozero` and `python3-lgpio` from apt, creates a
`gate-remote` system user in the `gpio` group, puts the app in
`/opt/gate-remote`, and enables the systemd service. On first run it copies
`.env.example` to `/etc/gate-remote/gate-remote.env` — **edit that file**, then
`sudo systemctl restart gate-remote`. Re-run the script to deploy changes.

```bash
ssh pi@192.168.0.20 journalctl -u gate-remote -f    # live log
```

## Exposing it through the cluster

The Pi is not a cluster node. `k8s/gate-ingress.yaml` defines a Service with no
selector and an EndpointSlice pointing at the Pi's IP, so nginx-ingress
forwards `gate.wleklinski.org` straight to it.

1. Set the Pi's real IP in the EndpointSlice (`192.168.0.20` is a placeholder).
2. `kubectl apply -f k8s/gate-ingress.yaml`

## Trying it

```bash
# Get a token (password grant via the testing client — not for the mobile app)
TOKEN=$(curl -s https://keycloak.wleklinski.org/realms/homelab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=gate-remote-cli \
  -d username=wjc --data-urlencode password="$PASSWORD" | jq -r .access_token)

curl -i -X POST https://gate.wleklinski.org/trigger -H "Authorization: Bearer $TOKEN"
```

| Response | Meaning |
|---|---|
| `202` | Gate pulsed |
| `401` | No token, bad signature, expired, wrong issuer or audience — the body says which |
| `403` | Valid token, but the user lacks `RESIDENT` |
| `429` | Too soon after the last open; see `Retry-After` |
| `502` / `504` from nginx | The Pi is down or unreachable from the cluster |
