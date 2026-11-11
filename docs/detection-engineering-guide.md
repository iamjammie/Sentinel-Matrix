# Detection Engineering Guide

## The scenario model

Sentinel Matrix generates detections from a **scenario knowledge base**. Each technique can have
several **distinct detection scenarios**, each with its own detection objective and logic — not
renamed copies. For example, Kerberoasting (T1558.003) ships eight scenarios: abnormal service
ticket volume, weak (RC4) encryption-type requests, unusual source host, honeytoken SPN, tooling
indicators, privileged/dormant accounts, an identity+endpoint correlation, and a statistical
baseline deviation.

A scenario is defined defensively — as **telemetry field predicates** (what the SIEM observes), an
optional aggregation, false-positive notes, tuning guidance, and validation test cases. It never
encodes attacker payloads.

## Generating detections

*Rule Generator*:

1. Enter a technique (or click *Pick an uncovered technique*).
2. Choose the target SIEM and environment profile.
3. *Generate scenarios* — each scenario renders to Sigma, Splunk SPL, Sentinel KQL, Elastic
   KQL/ES\|QL, a QRadar specification, SIEM-neutral spec, or JSON. Switch formats per scenario.
4. Add scenarios to the **engineering workbench** to track them through the lifecycle.

### Maturity labels

Generated output is labelled so you never mistake a draft for a deployed detection:

`generated_specification → syntax_validated → deployment_ready → tested`

The platform **never deploys** rules. Deployment is a manual, change-controlled step in your SIEM.

## Authoring custom scenarios

*Rule Generator → Author custom scenario*. Define the technique, logic type, data sources, event
IDs, and field conditions (`field op value`, operators: `eq, contains, endswith, ne, gt, in`).
Custom scenarios persist locally and appear in generation, coverage and validation.

## Validation

A detection is only **validated** after an executed test case passes. *Detection Validation*:

1. Select an imported rule or a generated detection.
2. Load the bundled test cases (or paste your own test events as JSON).
3. *Execute* — the app evaluates each event against the detection logic locally and records
   PASS / FAIL / PARTIAL / NOT_EXECUTED / INCONCLUSIVE as validation evidence.

The workbench **never runs attack simulations or launches payloads**. You can import authorised
**Atomic Red Team / CALDERA** results as external validation evidence.

## Lifecycle

*Detection Lifecycle* manages detections across 11 stages (Proposed → … → Operational → Requires
Tuning → Deprecated → Archived) with version history, comments, approvals and a full audit trail.

## Quality & effectiveness

- *Rule quality* scores eight weighted components (logic completeness, telemetry availability,
  mapping accuracy, scenario diversity, operational status, validation evidence, configuration,
  tuning). A rule is **not** rated highly just for being enabled.
- *Operational effectiveness* flags excessive alerting, recurring offense sources, missing
  telemetry and stale sources — but does **not** condemn a never-triggered rule on that basis
  alone (observation window, expected frequency, telemetry and purpose are weighed).

## Good practice

- Prioritise gaps by the combined priority score, not raw counts.
- Confirm inferred mappings before trusting coverage.
- Onboard the telemetry that unlocks the most techniques first (*Log Source Intelligence →
  Onboarding plan*).
- Build attack-chain correlation only once individual stages are reasonably covered.
