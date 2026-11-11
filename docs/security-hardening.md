# Security Hardening Guide

## Application security model

Imported rule files, API responses and uploaded datasets are treated as **untrusted input**.

- **Safe JSON parsing** with size limits and prototype-pollution key stripping (`__proto__`,
  `constructor`, `prototype` are dropped).
- **XML XXE protection** — documents containing `<!DOCTYPE>`/`<!ENTITY>` are rejected; parsing uses
  `DOMParser` which does not resolve external entities.
- **No unsafe HTML insertion** — the UI is built with a DOM helper that sets `textContent` and a
  whitelisted attribute set; no `innerHTML` with untrusted data.
- **No `eval`, no `new Function`**, no dynamic code execution. (Verified by the test suite.)
- **No automatic rule deployment.** Generated rules are specifications; deployment is manual.
- **No external network dependencies** — nothing is fetched from the internet.

Credentials for live audit are **never** persisted by the HTML app (not in `localStorage` or
IndexedDB) and are excluded from workspace backups.

## Local audit agent

The agent is the only component that handles SIEM credentials. Harden it as follows:

- **Bind to localhost.** Default is `127.0.0.1`. A loopback guard rejects non-local clients even if
  bound to `0.0.0.0`, unless you explicitly pass `--allow-remote` (not recommended).
- **Restrict origins.** CORS allows only `null` (file://) and localhost origins.
- **Read-only.** The agent exposes no endpoints that mutate SIEM state. It issues only read
  (GET-style) SIEM calls. There is no write mode.
- **No shell, no proxy.** There are no shell-execution endpoints and no general proxy; the agent
  calls only the specific SIEM REST endpoints per adapter.
- **Credential storage.** Prefer the OS keyring (`keyring` package → Windows Credential Manager /
  macOS Keychain / Secret Service). If you opt into a file store (`cred_path`), it is written
  `0600`. Tokens are never written to logs — a redaction filter scrubs any log line mentioning a
  secret.
- **Least privilege.** The SIEM API token should have the minimum read permissions needed (rules,
  log sources, offenses). See [qradar-api-configuration.md](qradar-api-configuration.md).
- **TLS.** Certificate verification is on by default. For private CAs, add the CA to the agent
  host's trust store rather than disabling verification.
- **Timeouts & rate limiting.** Requests use a 30s timeout; HTTP 429 triggers a bounded backoff.
- **No API docs surface.** The agent disables its OpenAPI/Swagger endpoints.

## Deployment checklist

- [ ] Agent bound to `127.0.0.1`, `--allow-remote` **not** set.
- [ ] SIEM token is read-only and scoped minimally.
- [ ] TLS verification enabled; private CA trusted on the agent host.
- [ ] Credentials in OS keyring, or a `0600` file on an encrypted volume.
- [ ] Agent runs as a non-privileged service account.
- [ ] Host firewall blocks inbound to the agent port from the network.
- [ ] Workspace backups stored securely (they contain assessment data, not credentials).

## Removing stored credentials

`POST /api/creds/remove` (or delete the keyring entry) removes a stored token. The app's *SIEM
Live Audit* never writes tokens; clearing the browser site data removes any cached connection
metadata (host/port only).
