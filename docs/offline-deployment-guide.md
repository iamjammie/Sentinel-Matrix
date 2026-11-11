# Offline / Air-Gapped Deployment Guide

Sentinel Matrix is designed for air-gapped enterprise and defence environments.

## Standalone application

The HTML app has **zero** network dependencies — no CDNs, Google Fonts, external CSS/JS, remote
APIs or internet images. Everything (code, ATT&CK/D3FEND/CAPEC/Kill Chain data, scenario templates,
Sigma sample pack, fonts via system stack) is bundled in the single file.

**Transfer:** copy `sentinel-matrix.html` onto the air-gapped host (approved removable media or a
one-way transfer). Open it in a browser. Done.

**Verify no external calls** (optional): open the browser DevTools *Network* tab and reload — you
should see only the local file load, no outbound requests.

## Framework updates offline

To update ATT&CK without internet:

1. On an internet-connected machine, download the official MITRE STIX 2.1
   `enterprise-attack.json`.
2. Transfer it to the air-gapped host.
3. *Framework Database → Import framework package* → review the diff (added/removed/renamed) →
   approve. Previous versions are retained for rollback.

The bundled data packages in `dist/data-packages/` can also be re-imported or distributed
separately.

## Local audit agent offline

To run live auditing air-gapped, pre-stage the Python wheels:

On an internet-connected machine matching the target OS/Python:

```bash
pip download -r agent/requirements.txt -d wheels/
```

Transfer `wheels/` and `agent/` to the air-gapped host, then:

```bash
pip install --no-index --find-links wheels/ -r agent/requirements.txt
python agent/sentinel_matrix_agent.py
```

The agent only talks to your in-network SIEM and to the local app — it needs no internet.

## Persistence & portability

Workspaces live in the browser IndexedDB. To move an assessment between air-gapped hosts, use
*Settings → Data Management → Export workspace* (portable JSON, credentials excluded) and *Restore*
on the other host.

## Hardening

Follow [security-hardening.md](security-hardening.md). For the strictest environments, keep the
agent bound to `127.0.0.1`, store credentials in the OS keyring, and never pass `--allow-remote`.
