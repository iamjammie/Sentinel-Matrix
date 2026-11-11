# Sentinel Matrix — Local SIEM Audit Agent

A small, **read-only** FastAPI service that runs inside your network and brokers SIEM REST APIs for
the Sentinel Matrix standalone app, so the browser never holds credentials and the SIEM is only
ever read.

## Install & run

```bash
pip install -r requirements.txt
cp config.example.yaml config.yaml     # optional
python sentinel_matrix_agent.py --host 127.0.0.1 --port 8787
```

Health check: `GET http://127.0.0.1:8787/health`.

## Supported platforms

IBM QRadar (priority), Splunk Enterprise Security, Microsoft Sentinel, Elastic Security. Each is a
modular adapter in `siem_adapters.py` implementing authentication, connection validation, API
version/capability detection, rule/log-source/offense retrieval, pagination, rate-limit handling,
error handling and normalisation.

## API

| Method | Path | Purpose |
|---|---|---|
| GET  | `/health` | Liveness, version, read-only flag, supported platforms |
| POST | `/api/siem/connect` | Validate connection, authenticate, detect capabilities |
| POST | `/api/siem/audit` | Retrieve rules + log sources + offenses + alerts (one call) |
| POST | `/api/siem/rules` | Rules only |
| POST | `/api/siem/offenses` | Offenses only |
| POST | `/api/siem/logsources` | Log sources only |
| GET  | `/api/siem/audit/status` | Audit status (synchronous model) |
| GET  | `/api/siem/audit/results` | Notes on result delivery |
| POST | `/api/creds/save` | Store a token in the OS keyring (optional) |
| POST | `/api/creds/remove` | Remove a stored token |

### Request body (connect/audit)

```json
{
  "platform": "qradar",
  "host": "qradar.corp.local",
  "port": 443,
  "api_version": "19.0",
  "auth_method": "token",
  "token": "READ-ONLY-SEC-TOKEN",
  "tls_verify": true,
  "read_only": true
}
```

`token` is used for the request only and is not persisted unless you explicitly call
`/api/creds/save`. For Microsoft Sentinel, set `host` to the ARM resource path
(`subscriptions/.../resourceGroups/.../providers/Microsoft.OperationalInsights/workspaces/<ws>`)
and `token` to a bearer token.

## Security

Read-only by design; localhost-only by default; credentials via OS keyring or a `0600` file;
secret-redacting logs; no shell/proxy endpoints; TLS verification on. See
[`../docs/security-hardening.md`](../docs/security-hardening.md).

## Windows / Linux deployment

- **Windows:** run under a non-privileged service account (e.g. via NSSM or Task Scheduler). The
  `keyring` package uses Windows Credential Manager automatically.
- **Linux:** run as a systemd service bound to `127.0.0.1`; install `keyring` + a Secret Service
  provider, or use a `0600` `cred_path` on an encrypted volume.

Example systemd unit:

```ini
[Unit]
Description=Sentinel Matrix Audit Agent
After=network.target
[Service]
ExecStart=/opt/sentinel/.venv/bin/python /opt/sentinel/agent/sentinel_matrix_agent.py
User=sentinel
Restart=on-failure
[Install]
WantedBy=multi-user.target
```
