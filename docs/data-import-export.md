# Data Import / Export Guide

## Imports

| Data | Where | Formats |
|---|---|---|
| Detection rules | Rule Import & Inventory | JSON, NDJSON, CSV, Sigma YAML, QRadar XML, `savedsearches.conf`, ARM |
| Log sources | Log Source Intelligence | JSON, CSV |
| Assets (CMDB/AD/SCCM/EDR/IPAM) | Enterprise Asset Context | JSON, CSV |
| Offenses / Alerts | Offense & Alert Analytics | JSON, CSV |
| Threat-intel relevance | Settings → Threat Intelligence | JSON `{ "T1558.003": 90, ... }` |
| ATT&CK (full) | Framework Database | STIX 2.1 bundle, or native dataset JSON |
| Validation evidence | Detection Validation | JSON (Atomic Red Team / CALDERA results) |
| Workspace restore | Settings → Data Management | Sentinel Matrix workspace JSON |

### Rule CSV example

```csv
rule_id,rule_name,severity,enabled,technique,log_sources,query,description
R-001,Kerberoasting - RC4 TGS,high,true,T1558.003,windows_security,"EventCode=4769 Ticket_Encryption_Type=0x17","Detects RC4 service tickets"
```

Recognised column aliases include `name/title`, `enabled/status/disabled`, `technique/techniques/
mitre`, `log_sources/index/sourcetype`, `query/search/detection_logic`, and more. Unknown columns
are preserved in the original content and surfaced in the import summary.

### Assets CSV example

```csv
hostname,ip,os,business_unit,zone,criticality,log_sources
dc01,10.2.0.10,Windows Server 2022,IT,Domain Controller Zone,critical,windows_security|active_directory|edr
```

## Exports

- **Rule inventory** — JSON / CSV (filtered or full).
- **Coverage** — CSV / JSON; **ATT&CK Navigator layer** JSON from the matrix.
- **Gap analysis** — CSV / JSON.
- **Reports** — HTML, Markdown, JSON, CSV; **PDF** via the browser print dialog (*Print / PDF*).
- **Generated detections** — per-format (Sigma/SPL/KQL/QRadar spec/JSON) or the whole workbench.
- **Validation results**, **lifecycle audit trail** — JSON.
- **Workspace backup** — portable JSON of the entire workspace (optionally including framework
  datasets). **Credentials are never included.**

## XLSX-compatible output

CSV exports open directly in Excel. For the reports, the HTML export renders cleanly in Excel/Word
and the CSV export of any tabular section is spreadsheet-ready.

## Integrity

Workspace backups carry an FNV-1a checksum; restore verifies it and refuses mismatched or
newer-schema backups. Run *Settings → Data Management → Integrity check* to validate internal
references (e.g. coverage/gaps pointing at known techniques).
