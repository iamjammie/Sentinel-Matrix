# SIEM Integration Guide

There are two ways to get SIEM data into Sentinel Matrix:

## A. Offline rule import (no agent, works air-gapped)

Export your rules from the SIEM and import the files. Per-platform format adapters are built in.

| SIEM | How to export | Format |
|---|---|---|
| **IBM QRadar** | Content Management Tool (CMT) export, or API `GET /api/analytics/rules` saved to JSON | XML / JSON |
| **Splunk ES** | `GET /servicesNS/-/-/saved/searches?output_mode=json`, or copy `savedsearches.conf` | JSON / conf |
| **Microsoft Sentinel** | Export analytics rules as ARM template, or API list | JSON (ARM) |
| **Elastic Security** | Kibana → Rules → Export, or `GET /api/detection_engine/rules/_find` | NDJSON / JSON |
| **Sigma** | Any `.yml` Sigma rule(s) | YAML |
| **Generic** | Any structured JSON/CSV with rule fields | JSON / CSV |

The importer auto-detects format and platform, normalises to a common schema, preserves the
original rule, and reports parse errors, duplicates, unmapped rules and quality issues.

> We do **not** claim universal support for every export variant. Each adapter targets documented
> export structures and degrades gracefully; unrecognised records are reported, never silently
> dropped.

## B. Live audit via the local agent (read-only)

For continuous or on-demand live auditing, run the local Python agent inside your network and
connect from *SIEM Live Audit*. The agent brokers the SIEM REST API so the browser never holds
credentials and the SIEM is only ever read.

Initial integration priority: **IBM QRadar**, then Splunk ES, Microsoft Sentinel, Elastic Security.

### Live audit flow

1. Start the agent (`python sentinel_matrix_agent.py`).
2. *SIEM Live Audit → Connection* — set the agent URL, platform, host/IP, port, and paste a
   **read-only** API token. Click *Test connectivity & authenticate*.
3. The agent performs capability detection (which endpoints/fields exist on your version).
4. *Audit workflow → Run live audit* — the agent retrieves rules, log sources and offenses; the app
   normalises them and runs coverage, effectiveness and gap analysis, then offers an audit report.

The default live audit **never** modifies rules, deletes offenses, creates rules or deploys
configuration. See [qradar-api-configuration.md](qradar-api-configuration.md) and
[security-hardening.md](security-hardening.md).

## Field normalisation

All sources map onto one internal schema (`rule_id`, `rule_name`, `detection_logic`,
`attack_techniques`, `log_source_types`, `event_ids`, `threshold`, `time_window`,
`grouping_fields`, `severity`, `enabled_status`, lifecycle/validation metadata, and the preserved
`original_rule_content`). Unknown field names encountered during import are surfaced in the import
summary so you can extend mappings.
