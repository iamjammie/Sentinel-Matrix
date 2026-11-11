# QRadar API Configuration Guide

Sentinel Matrix prioritises IBM QRadar. This guide covers read-only API access for the live audit
agent and QRadar rule export/generation.

## 1. Create a read-only authorized service token

1. In QRadar: **Admin → User Management → Authorized Services → Add Authorized Service**.
2. Assign a **security profile** and **user role with read-only permissions** sufficient for:
   - *Offenses* (view),
   - *Log Activity* / *Log Sources* (view),
   - *Custom Rules* (view) — required to read CRE rules via the API.
3. Note the generated **token (SEC header value)**. Treat it as a secret.

> Grant the least privilege that still allows reading rules, log sources and offenses. The agent
> never needs write/admin permissions.

## 2. API endpoints used (read-only)

The QRadar adapter uses documented REST endpoints and performs **capability detection** — if an
endpoint or field is unavailable on your QRadar version, it degrades gracefully instead of failing.

| Purpose | Endpoint |
|---|---|
| Version / about | `GET /api/system/about` |
| CRE rules | `GET /api/analytics/rules` (+ `/{id}` for tests where exposed) |
| Building blocks | `GET /api/analytics/building_blocks` |
| Log sources | `GET /api/config/event_sources/log_source_management/log_sources` |
| Offenses | `GET /api/siem/offenses` |
| Reference sets | `GET /api/reference_data/sets` |

Pagination uses the QRadar `Range: items=start-end` header. The adapter sends an API `Version`
header (default `19.0`; override in the connection form if your appliance differs).

Fields requested from rules: `id, name, type, enabled, owner, origin, creation_date,
modification_date, identifier`. Rule *tests* are read per-rule where the endpoint exposes them;
some versions do not expose full test text via the API, in which case the specification is built
from the available metadata.

## 3. Connection settings in the app

*SIEM Live Audit → Connection*:

- **Agent URL** — where the local agent listens (default `http://127.0.0.1:8787`).
- **Platform** — IBM QRadar.
- **Hostname / IP** — your QRadar console.
- **API port** — usually `443`.
- **API version** — e.g. `19.0` (leave blank to use the agent default).
- **TLS verification** — keep enabled; install your QRadar CA on the agent host if using a private
  CA (see troubleshooting).
- **API token** — the SEC token. It is sent to the local agent only and is **not** stored by the
  HTML app.

## 4. QRadar rule generation (specifications, not fabricated syntax)

QRadar custom rules are built in the **Rule Wizard (CRE)**. Sentinel Matrix does **not** fabricate
CRE syntax. The Rule Generator produces a precise **QRadar rule specification** listing:

- the required log sources and QIDs to map,
- each rule **test** to add (with the exact field/value/operator), in order,
- counter/sequence parameters (threshold, grouping fields, time window),
- building-block and reference-set dependencies,
- rule response (dispatch new event; offense indexing field) — never auto-remediation,
- tuning guidance and known false positives.

Build the rule in the Rule Wizard from this specification, keep it **disabled** until validated,
then enable after your validation test cases pass.

## 5. TLS with a private CA

If your QRadar uses a certificate from an internal CA, add that CA to the agent host's trust store
(or point `httpx` at the CA bundle). Do **not** disable TLS verification in production.
