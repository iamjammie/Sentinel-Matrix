# SENTINEL MATRIX

**Enterprise SIEM Detection Coverage Intelligence, Rule Audit & Detection Engineering Platform**

> *See the Gaps. Engineer the Defence. Detect the Adversary.*

Sentinel Matrix is an **offline-first, single-file** detection intelligence workbench for SOC
analysts, SIEM administrators, detection engineers, threat hunters and security architects. It
assesses whether an enterprise's existing SIEM detection rules are adequate to detect known
adversary techniques, identifies blind spots, and helps engineer, validate and manage new
detections — all without an internet connection.

It is **not** a static dashboard. Every button, filter, import, export, chart and assessment is
functional and runs locally in your browser against your real imported data.

Part of the offline, ATT&CK-mapped security tooling family alongside
[FluxHunt](https://github.com/iamjammie/FluxHunt) (PCAP hunting),
[HostHunt](https://github.com/iamjammie/HostHunt) (host triage),
[TTP-Nexus](https://github.com/iamjammie/TTP-Nexus) (TTP knowledge) and
[hunt-sage](https://github.com/iamjammie/hunt-sage) (hunt knowledge hub).

---

## What's in the box

```
sentinel-matrix/
├── dist/
│   ├── sentinel-matrix.html        ← the primary application (single, portable HTML file)
│   └── data-packages/              ← the bundled datasets, also shipped separately
├── agent/                          ← optional local Python SIEM audit agent (read-only)
│   ├── sentinel_matrix_agent.py
│   ├── siem_adapters.py            ← QRadar, Splunk, Sentinel, Elastic adapters
│   ├── credential_store.py
│   ├── requirements.txt
│   └── config.example.yaml
├── src/                            ← modular source (CSS + 24 JS modules + HTML template)
├── data/                           ← dataset generators (Python) + generated JSON
├── scripts/
│   └── validate_data.py            ← offline validator for every bundled dataset
├── docs/                           ← full documentation set
├── tests/                          ← Node engine tests, Playwright browser tests, agent pytest
├── .github/workflows/validate.yml  ← CI: syntax, datasets, engines, build freshness, self-contained
└── build.js                        ← assembles src/ + data/ into dist/sentinel-matrix.html
```

## Quick start

1. **Run the app** — open `dist/sentinel-matrix.html` in any modern browser (Chrome, Edge,
   Firefox). No installation, no server, no internet required. It works from `file://`.
2. **Load demo data** (optional) — on the Command Centre click *Load demo data* to explore every
   module with clearly-marked `DEMO DATA`.
3. **Import your rules** — *Rule Import & Inventory → Import workflow*. Supported formats: JSON,
   NDJSON, CSV, Sigma YAML, QRadar XML, Splunk `savedsearches.conf`, Elastic/Sentinel exports.
4. **Run a full assessment** — *Command Centre → Run full assessment*. This computes ATT&CK
   coverage, detection gaps and prioritisation.
5. **Explore** — ATT&CK matrix, gap analysis, rule generator, validation, log source
   intelligence, attack chain analysis, reports.
6. **(Optional) Live audit** — deploy the local Python agent inside your network and connect to
   IBM QRadar / Splunk ES / Microsoft Sentinel / Elastic Security, read-only.

## Core capabilities

| Module | What it does |
|---|---|
| **Command Centre** | Executive + operational dashboard driven by real analysis results. |
| **Rule Import & Inventory** | Multi-format ingestion, normalisation to a common schema, duplicate & quality analysis. |
| **Detection Coverage** | Weighted, six-dimension ATT&CK coverage (mapping, configured, operational, validated, telemetry, asset). |
| **ATT&CK Matrix** | Navigator-style interactive matrix; exports a Navigator layer. |
| **Gap Analysis** | Prioritised gaps with telemetry, asset exposure, and recommended action. |
| **Rule Generator** | Deterministic, template-driven generation of multiple detection scenarios per technique, rendered to Sigma / SPL / KQL / ES\|QL / QRadar spec. |
| **Detection Engineering / Lifecycle** | Workbench and 11-stage lifecycle with full audit trail. |
| **Detection Validation** | Executes test cases locally; never runs attacks. |
| **SIEM Live Audit** | Read-only audit via the local agent (QRadar prioritised). |
| **Offense & Alert Analytics** | Operational effectiveness without unfairly punishing never-triggered rules. |
| **Log Source Intelligence** | Telemetry inventory, health, and onboarding plans. |
| **Enterprise Asset Context** | CMDB/AD/SCCM/EDR/IPAM import; per-zone and per-platform coverage. |
| **Attack Chain Analysis** | Coverage across multi-stage adversary behaviour. |
| **Framework Database** | Offline ATT&CK, D3FEND, CAPEC, Kill Chain, Sigma; STIX import. |
| **Reports & Exports** | 12 report types; PDF (print), HTML, JSON, CSV, Markdown, XLSX-ready. |

## Design principles

- **Offline-first.** Zero internet dependencies: no CDNs, no external fonts, no remote APIs. All
  code and intelligence data are bundled locally. Suitable for air-gapped environments.
- **Real functionality.** No fake buttons, no hardcoded results. Demo data is always labelled.
- **Enterprise scale.** Virtualised tables, IndexedDB persistence, incremental analysis — tested
  with 10,000+ rules.
- **Security-conscious.** Imported files and API responses are treated as untrusted: strict
  validation, safe JSON parsing, XML XXE protection, HTML-sanitising DOM construction, **no
  `eval`, no `Function()`**, no automatic rule deployment, read-only API access by default.

## Building from source

```bash
node build.js          # assembles dist/sentinel-matrix.html + dist/data-packages/
```

Regenerate the datasets (optional):

```bash
cd data
python3 build_frameworks.py && python3 build_scenarios.py && python3 build_sigma_pack.py
```

## Data validation & CI

Every bundled dataset is validated offline, in the same spirit as the rest of the Hunt suite
(`hunt-sage/scripts/validate_rules.py`, `PhotonWire` codec/integrity checks):

```bash
python3 scripts/validate_data.py   # ATT&CK ids/tactics/platforms, scenario schema, cross-refs
```

`validate_data.py` checks that ATT&CK tactic/technique IDs are well formed and unique, every
technique references known tactics (and sub-techniques name a real parent), referenced data
components and log-source types exist, each detection scenario has a unique id, a known
`logic_type`, an allowed severity, real detection logic (a selection or an aggregation) and
match/no_match test cases, and that D3FEND/CAPEC/Kill-Chain cross-references point at real ATT&CK
IDs.

`.github/workflows/validate.yml` runs on every push/PR with `permissions: contents: read` and gates:

- `node --check` on every JS module and `build.js`;
- `scripts/validate_data.py` (dataset schema/integrity);
- the engine unit tests;
- **dataset freshness** — regenerate `data/*.json` and fail on drift;
- **build freshness** — rebuild `dist/sentinel-matrix.html` and fail if it changed (committed build must match source);
- **self-contained check** — grep the built file for any external `src=`/`href=` / Google Fonts / `@import url(https…)` and fail if found;
- the Python agent: `py_compile` + `pytest`.

## Testing

```bash
node tests/js/engine.test.js      # 55 engine unit tests (no browser needed)
node tests/js/browser.test.js     # Playwright acceptance tests (AT1–AT9)
python3 scripts/validate_data.py  # bundled-dataset validation
python3 -m pytest tests/agent     # agent tests
```

## Documentation

See [`docs/`](docs/): installation, user guide, SIEM integration, QRadar API configuration,
detection engineering, offline/air-gapped deployment, security hardening, troubleshooting, and
data import/export.

## Important notes on accuracy

- The bundled ATT&CK dataset is a **compact offline representation** (full technique/sub-technique
  IDs, names, tactics, platforms, data components; abbreviated descriptions). Import the official
  MITRE STIX 2.1 `enterprise-attack.json` via *Framework Database → Import* for the complete corpus.
- Generated rules are **specifications** by default, labelled by maturity
  (*generated → syntax-validated → deployment-ready → tested*). The platform never deploys rules.
- For **QRadar**, output is an explicit **rule specification** for the Rule Wizard (CRE), not
  fabricated CRE syntax.
- **Threat-intelligence relevance** in gap prioritisation is only used when you import an intel
  dataset; otherwise it is marked *unknown*.
