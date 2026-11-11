# User Guide

## Orientation

- **Left sidebar** — 17 modules grouped into Operations, Engineering, SIEM & Telemetry, and
  Knowledge & Output. Collapse it with the ☰ button.
- **Top bar** — global search (press `/`), SIEM connection status, audit mode, active profile,
  last assessment time, notifications.
- **Drawer / modals** — detail panels open on the right; press `Esc` to close.

## Typical workflow

1. **Set your environment profile** — *Settings → Analyst & profile*. The profile (e.g. *Large
   Active Directory Enterprise*) decides which techniques are *applicable* and what telemetry is
   expected. Profiles are editable.
2. **Import rules** — *Rule Import & Inventory → Import workflow*. Drop files, pick the SIEM
   platform (or auto-detect), review the import summary (parsed, duplicates, unmapped, quality
   flags), then approve.
3. **Add context (optional but recommended):**
   - *Log Source Intelligence* — import or seed your telemetry inventory. Coverage confidence
     depends on knowing what you actually collect.
   - *Enterprise Asset Context* — import CMDB/AD/SCCM/EDR/IPAM for per-zone/per-platform coverage.
   - *Settings → Threat Intelligence* — import relevance scores to weight gap prioritisation.
4. **Run the assessment** — *Command Centre → Run full assessment*. This computes coverage, gaps
   and prioritisation.
5. **Investigate:**
   - *Detection Coverage* / *ATT&CK Matrix* — where you are strong and weak.
   - *Gap Analysis* — prioritised, actionable gaps.
   - *Rule Generator* — generate multiple detection scenarios for uncovered techniques.
   - *Detection Validation* — execute test cases to turn coverage into *validated* coverage.
6. **Report** — *Reports & Exports* — produce executive and detailed reports (PDF/HTML/MD/JSON/CSV).

## Reading coverage

Coverage is **not a rule count**. Each applicable technique is classified:

| Class | Meaning |
|---|---|
| **Validated** | An enabled, telemetry-backed rule passed an executed validation test. |
| **Fully covered** | Enabled rules + available telemetry + acceptable logic cover the main scenarios. |
| **Partially covered** | Only some scenarios/variants are addressed. |
| **Weak coverage** | Rules exist but are disabled, lack telemetry, are low quality, or inferred-only. |
| **Unvalidated** | Enabled & mapped, but telemetry availability is unknown. |
| **Not covered** | No rule maps to the technique or its sub-techniques. |
| **Not applicable** | Technique's platforms are outside the active profile. |

The six **coverage dimensions** (mapping, configured, operational, validated, telemetry, asset)
each have an explanation — click a dimension card in *Detection Coverage* to see its methodology and
the lowest-scoring techniques. The **composite** is a configurable weighted indicator (adjust
weights in *Settings → Scoring*).

## Inferred vs explicit mappings

Rules without an explicit ATT&CK mapping may be mapped by **inference** (keyword knowledge base or a
technique ID found in text). Inferred mappings are shown with **dashed tags** and reduce coverage
confidence — they are never treated as proof. Confirm and make them explicit where correct.

## Global search & advanced filters

Press `/` to search across rules, techniques, gaps, assets, offenses and scenarios. In the rule
inventory you can use boolean filters: `technique:T1558 AND platform:qradar NOT disabled`. Supports
`AND`, `OR`, `NOT`/`-`, parentheses, quotes, and `field:value`. Save filters for reuse.

## Keyboard

- `/` focus search · `Esc` close search/drawer.

## Data management

*Settings → Data Management*: export/restore the full workspace as portable JSON (credentials are
never included), run integrity checks, view storage usage, load/clear demo data, or clear
everything. See [data-import-export.md](data-import-export.md).
