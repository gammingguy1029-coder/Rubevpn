# RubeVPN V1

Personal VPN management system: FastAPI backend, authenticated dark dashboard,
diagnostics, and a modular WireGuard provider interface.

> **Milestone 0 finding:** GitHub-hosted Windows runners cannot host a public
> WireGuard endpoint. See [Feasibility](#milestone-0--feasibility) below.
> Milestone 1 builds the host-agnostic foundation with honest status reporting.
> No VPN handshake or connected client is simulated by the dashboard.

**Full engineering, deployment and reuse guide:** [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)

## Status of acceptance criteria

| Capability | State |
|---|---|
| Repository structure, CI workflows | Implemented |
| Python 3.12 backend, config validation, structured logs | Implemented |
| Authenticated dashboard with real backend data | Implemented |
| API authentication / invalid credentials rejected | Implemented |
| Secret redaction in logs | Implemented |
| Network diagnostics and preflight scripts | Implemented |
| Windows WireGuard provider + setup scripts | Implemented, unit tested locally |
| Config/API/log/Windows/startup tests | 60 passing locally |
| Experimental userspace WireGuard + UDP tunnel | Handshake verified via `peercheck` (`VERIFY_OK`) |
| One-click `start.bat` / `stop.bat` | Implemented; verified handshake gate, clear ONLINE banner, QR auto-opens |
| CI workflows on GitHub | Not yet verified (no remote push performed) |
| Native WireGuard on an eligible public host | Code ready, not verified on real infrastructure |
| DNS / IPv6 leak prevention verification | Not implemented |
| Session expiry, shutdown detection, reconnection | Not implemented |
| Real-infrastructure integration tests | Not verified |

## Milestone 0 — feasibility

Measured on a GitHub-hosted Windows Server 2022 RDP runner:

- Public address `52.190.x.x` is a **shared outbound NAT** address, not bound to any local interface.
- STUN binding returned an **ephemeral** mapped port. Binding the socket to UDP `51820` still produced a different external port — the NAT does not preserve ports, so a public client cannot reach the configured WireGuard port.
- `IPEnableRouter = 0` and the session is not elevated, so IP forwarding/NAT and WireGuard installation are unavailable.
- Inbound access to the runner arrives through the internal/Tailscale path, not the public IP.
- Outbound TCP, DNS, and UDP work normally.

Conclusion: a **compatible authorized host** (public IPv4, inbound UDP, elevation, IP forwarding/NAT) is required for Milestones 2–6. The VPN layer is isolated behind `VpnProvider` so that host can be substituted without rewriting the API or dashboard.

## Repository structure

```
RubeVPN/
├── .github/workflows/{preflight.yml,tests.yml}
├── backend/
│   ├── requirements.txt
│   └── app/
│       ├── main.py, config.py, logging_config entry in monitoring/events.py
│       ├── api/{health,auth,status}.py
│       ├── monitoring/{models,health,events}.py
│       ├── services/vpn_provider.py
│       └── security/{auth,redaction}.py
├── dashboard/{index.html,style.css,app.js}
├── scripts/{preflight.py,diagnostics.py}
├── tests/{test_api.py,test_config.py,test_logging.py,conftest.py}
├── config/settings.example.json
├── logs/.gitkeep
├── .gitignore
├── README.md
└── LICENSE
```

## Local quick start

Requires Python 3.12+.

```powershell
python -m pip install -r backend/requirements.txt

# Generate an admin password hash (prompted; the password is never printed).
python scripts/preflight.py --hash-password

# Create a random session signing secret, then set both in the environment.
$env:RUBEVPN_ADMIN_USER = "admin"
$env:RUBEVPN_ADMIN_PASSWORD_HASH = "<hash from above>"
$env:RUBEVPN_SESSION_SECRET = "<random string of at least 32 characters>"
$env:RUBEVPN_COOKIE_SECURE = "false"   # set to true behind HTTPS

python -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000
```

Open `http://127.0.0.1:8000/`. Use a copy of `config/settings.example.json` at
`config/settings.json` to override settings; the committed example contains no secrets.

For remote access, terminate HTTPS at a reverse proxy and set
`RUBEVPN_COOKIE_SECURE=true`. Never expose the dashboard directly over plain HTTP.

## API

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/health` | public | Liveness, version, timestamp |
| POST | `/api/v1/auth/login` | CSRF token | Sign in, signed HttpOnly cookie |
| POST | `/api/v1/auth/logout` | admin + CSRF | Sign out |
| GET | `/api/v1/auth/session` | admin | Session check for the dashboard |
| GET | `/api/v1/status` | admin | Monitoring snapshot (real provider data) |
| GET | `/api/v1/events` | admin | Recent redacted structured events |
| GET | `/api/v1/diagnostics` | admin | Diagnostic checks |

Security: PBKDF2-SHA256 password hashing, HMAC-signed session tokens,
SameSite=Strict cookies, double-submit CSRF tokens, login rate limiting, Pydantic
input validation, and a redaction filter applied to every log record. Secrets
come only from environment variables / GitHub Actions secrets, never from the
settings file, repository, artifacts, dashboard URLs, or logs.

## Diagnostics

```powershell
python scripts/preflight.py            # human-readable, non-destructive
python scripts/preflight.py --json --save
python scripts/diagnostics.py --json
```

Preflight checks OS, Python, dependencies, config validity, existing
installation, port conflicts, elevation/IP forwarding, and network prerequisites.
It never overwrites credentials or configuration. Use `--strict` to make
blocking findings produce exit code 2; the default reports and exits 0 so CI can
publish the report without failing on expected hosted-runner limitations.

Diagnostics marks unverifiable items as `UNVERIFIED` rather than reporting
success. Inbound UDP requires an external probe.

## Tests

```powershell
python -m pytest -q
```

CI runs the same suite on `windows-latest` with Python 3.12, least-privilege
`contents: read` permissions, and no private keys in artifacts or logs.

## Windows WireGuard support

Target: an **elevated Windows host** with a public IPv4 address and inbound UDP
on the WireGuard port. The implementation is Windows-specific and uses
`wg.exe`, `wireguard.exe`, the `WireGuardTunnel$<interface>` Windows service,
`netsh`, PowerShell `New-NetNat`, and restricted ACLs.

Eligibility is checked before anything is changed:

```powershell
python scripts\setup_windows.py --json        # plan only, writes nothing
```

On an eligible host, from an **elevated** PowerShell, with a local
`config/settings.json` whose `vpn.endpoint_host` is the public IPv4:

```powershell
python -m pip install -r backend\requirements.txt
python scripts\setup_windows.py --json --apply
```

The script is idempotent: it generates server/client keypairs only when absent,
never overwrites existing keys or configs, and records created artifacts in
`%ProgramData%\RubeVPN\wireguard\setup-state.json`. Private keys are written
only to that administrator-only directory; they are never printed, logged,
served by the API, or placed in GitHub artifacts.
Safe rollback: `python scripts\setup_windows.py --cleanup`.

To activate real monitoring, set `vpn.provider` to `wireguard` in
`config/settings.json` and restart the app. The provider then reports:

- `ONLINE` only after a **real recent handshake** observed via `wg show`.
- `DEGRADED` when the tunnel runs but no peer has handshaked.
- `OFFLINE` when tools/service are missing.
- Client counts from `wg show` only; `null` when no data exists.

### Android (once an eligible host exists)

1. Install the official **WireGuard** app from Google Play.
2. Retrieve `%ProgramData%\RubeVPN\wireguard\phone.conf` as an administrator and
   import it **once** (file or QR generated locally). Do not email or upload it.
3. Enable the tunnel. The profile uses `AllowedIPs = 0.0.0.0/0`,
   explicit `DNS = 1.1.1.1`, and `PersistentKeepalive = 25`.
4. The app uses Android's standard `VpnService` permission — no root needed.
5. To change the endpoint, update the profile in the app; do not reuse leaked keys.

**Nothing in this section has been executed against a real public Windows
host.** Handshake, IPv4 routing, DNS behaviour, and reconnection remain
`UNVERIFIED` until tested there.

## Known performance constraints and fixes

- **gVisor RACK stall:** the vendored netstack disables TCP RACK recovery, which
  upstream could stall downloads for 14–21 s after brief packet loss
  ([MHSanaei/3x-ui#7177](https://github.com/MHSanaei/3x-ui/issues/7177), fix
  commit `e38ad52`).
- **MTU tuning:** `RUBEVPN_WG_MTU` accepts an integer `1200`–`1500` (default
  `1420`) and is written to both `server.env` and the Android profile
  (`MTU = <value>`). Invalid values fail with `CFG_INVALID`; try `1400` on
  CGNAT/relay links.
- **Android data path:** the official WireGuard app uses userspace
  `wireguard-go` through `VpnService` unless the device is rooted, so it cannot
  match native kernel throughput.
- **Free relay:** Pinggy publishes UDP tunnels with unlimited data, but they
  expire after ~60 minutes, change port on restart, and add a relay hop.
- **Realistic ceiling:** sustained 40–100 Mbps requires native WireGuard on a
  public-IP host with inbound UDP and IP forwarding/NAT.
- **Optional measurement:** run `python scripts/start_experimental.py --speedtest`
  to execute the bundled `speedtest.exe` after a successful handshake. It uses
  the verification peer's credentials and prints its output; a
  `SPEEDTEST_FAILED` error is reported but never blocks normal startup.

## Roadmap

1. **M0** — Feasibility (done, documented above).
2. **M1** — Foundation: repository, backend, dashboard, tests, CI (this release).
3. **M2** — WireGuard integration on an authorized host; real handshake evidence.
4. **M3** — One-time Android profile import, full-tunnel IPv4, explicit DNS, secure endpoint updates.
5. **M4** — Real handshake/health monitoring wired to dashboard refresh.
6. **M5** — Session expiry, shutdown detection, reconnection eligibility (claim only after a real restart test).
7. **M6** — Documentation, security review, V1 release checklist.

## Troubleshooting

| Symptom | Action |
|---|---|
| App fails at startup with `CFG_INVALID` | Set both security environment variables; check `config/settings.json`. For the experimental launcher, check that `RUBEVPN_WG_MTU` is an integer from 1200 to 1500. |
| Tunnel pages are slow or stall | Try `RUBEVPN_WG_MTU=1400` and `--speedtest`; for 40–100 Mbps use native WireGuard on a public-IP host. |
| Dashboard shows `OFFLINE` with `PUBLIC_ENDPOINT_MISSING` | Expected on hosted runners; deploy on an authorized host. |
| Login returns `CSRF_FAILED` | Reload the page so a fresh CSRF cookie is set. |
| Login returns `AUTH_RATE_LIMITED` | Wait one minute before retrying. |
| Connected clients shows "Unavailable (no real data)" | No VPN provider is active; this is intentional, not a display bug. |
