# Installation Guide

Sentinel Matrix has two parts: the **standalone HTML application** (required) and the **local
audit agent** (optional, only for live SIEM auditing).

## 1. Standalone application

No installation is required.

1. Copy `dist/sentinel-matrix.html` to the target machine (USB, file share, or secure transfer for
   air-gapped networks).
2. Double-click it, or open it in a browser via *File → Open*. It runs directly from `file://`.

**Supported browsers:** current Chrome, Edge, Firefox. A Chromium-based browser is recommended for
the largest datasets. Private/incognito windows disable IndexedDB persistence — the app still runs
but falls back to in-memory mode (a warning is shown) and data is lost on reload.

**System requirements:** any machine that runs a modern browser. For 10,000+ rule datasets, 4 GB
RAM is comfortable.

**Persistence:** data is stored in the browser's IndexedDB, scoped to the file's origin. Using the
same file path/URL on the same browser profile preserves your workspace across sessions. To move a
workspace between machines, use *Settings → Data Management → Export workspace*.

## 2. Optional local audit agent

Only needed for **live SIEM auditing**. The standalone app is fully functional without it.

**Requirements:** Python 3.11+.

```bash
cd agent
python -m venv .venv
# Windows:  .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
cp config.example.yaml config.yaml      # optional
python sentinel_matrix_agent.py --host 127.0.0.1 --port 8787
```

Verify: open `http://127.0.0.1:8787/health` — you should see `{"status":"healthy",...}`.

See [offline-deployment-guide.md](offline-deployment-guide.md) for air-gapped installs (offline pip
wheels) and [security-hardening.md](security-hardening.md) before any production use.

## Upgrading

Replace `sentinel-matrix.html` with the new build. Your IndexedDB workspace is preserved across
upgrades (the schema auto-migrates). Always export a workspace backup before a major upgrade.
