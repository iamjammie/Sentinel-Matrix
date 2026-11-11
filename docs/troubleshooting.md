# Troubleshooting

## Application

**"IndexedDB is unavailable; running in in-memory mode."**
You're in a private/incognito window or the browser blocks storage for `file://`. Data won't
persist across reload. Use a normal window, or export/restore the workspace manually.

**Import parsed 0 rules / many errors.**
- Check the *Import summary → Error report* and *Format adapters* table.
- Pick the correct SIEM platform instead of auto-detect if detection guessed wrong.
- CSV: ensure a header row. Sigma: valid YAML with `title` and `detection`. QRadar XML: a CMT
  export containing `<custom_rule>`/`<rule>` elements.
- Very large single JSON files: split into multiple files if the browser runs low on memory.

**Rules import but everything is "unmapped".**
Your rules carry no ATT&CK mapping and no technique IDs in text. Use *Rule Generator* mappings, or
add explicit `attack_techniques` to the export. Inferred mappings (dashed tags) appear only when a
keyword or technique ID is recognisable.

**Coverage says many techniques "Not applicable".**
The active environment profile's platforms exclude them. Change or edit the profile in
*Settings → Environment profiles*.

**Telemetry dimension is low / "log source inventory not loaded".**
Import or seed your log sources (*Log Source Intelligence → Seed from active profile* or import).
Without a telemetry inventory, coverage can't confirm a rule can actually fire.

**UI feels slow with huge datasets.**
Tables are virtualised and should stay responsive to 10k+ rules. If a specific view lags, narrow
with filters. Reload to clear transient memory pressure.

**"Boot error" on open.**
Ensure you opened the complete `sentinel-matrix.html` (≈780 KB). A truncated copy (partial
transfer) will fail. Re-copy the file.

## Live audit agent

**"Agent not reachable."**
Start the agent (`python sentinel_matrix_agent.py`) and confirm `http://127.0.0.1:8787/health`.
This is expected and harmless in a pure offline/standalone deployment — use offline rule import
instead.

**"Connection failed" to the SIEM.**
- Confirm host/IP, port and that the agent host can reach the SIEM.
- 401 → bad/expired token or insufficient permissions. 403 → token lacks read access to that
  resource.
- TLS errors with a private CA → add the CA to the agent host trust store (don't disable
  verification in production).

**QRadar returns fewer fields than expected.**
Field/endpoint availability varies by QRadar version; the adapter uses capability detection and
omits unavailable fields. Rule *test* text may not be exposed by the API on some versions — the
specification is then built from available metadata.

**CORS error in the browser console.**
The agent restricts origins to localhost/`null`. Open the app from `file://` or `http://localhost`.

## Tests

- `node tests/js/engine.test.js` — engine unit tests (no browser).
- `node tests/js/browser.test.js` — requires Playwright/Chromium.
- `python -m pytest tests/agent` — agent tests (live API tests skip if FastAPI isn't installed).
