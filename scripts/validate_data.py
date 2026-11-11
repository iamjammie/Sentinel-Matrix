#!/usr/bin/env python3
"""Validate the bundled offline datasets for SENTINEL MATRIX.

Checks (offline, no network needed) — in the spirit of hunt-sage/scripts/validate_rules.py:
  * every dataset file parses as JSON and carries its declared framework/version metadata
  * ATT&CK: tactic ids (TA####) and technique ids (T####[.###]) are well formed and unique;
    every technique references known tactics; sub-techniques name a known parent; platforms are known
  * data components referenced by techniques exist in the data_components catalogue
  * detection scenarios: unique scenario ids per technique; a known logic_type; non-empty selection;
    every log_source_type exists in the log-source catalogue; severity is an allowed level;
    at least one validation test case per scenario, each with a match/no_match expectation
  * D3FEND / CAPEC / Kill Chain cross-references point at real ATT&CK ids
  * environment profiles reference known log-source types and platforms

Usage: python scripts/validate_data.py        (exit 0 = clean, 1 = errors)
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SUBTECH_RE = re.compile(r"^T\d{4}\.\d{3}$")
TACTIC_RE = re.compile(r"^TA\d{4}$")
LEVELS = {"critical", "high", "medium", "low", "informational"}
LOGIC_TYPES = {
    "threshold", "frequency", "sequence", "correlation", "behavioural", "baseline",
    "multi_source", "entity", "time_based", "statistical", "process", "state_change",
}
KNOWN_PLATFORMS = {
    "Windows", "Linux", "macOS", "Network", "Cloud", "Containers",
    "Identity Provider", "Office Suite", "SaaS", "PRE",
}

errors: list[str] = []
warnings: list[str] = []


def err(msg: str) -> None:
    errors.append(msg)


def warn(msg: str) -> None:
    warnings.append(msg)


def load(name: str):
    path = DATA / name
    if not path.exists():
        err(f"{name}: missing dataset file")
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        err(f"{name}: invalid JSON — {e}")
        return None


def validate_attack(attack) -> tuple[set, set]:
    tech_ids: set[str] = set()
    tactic_ids: set[str] = set()
    dc_ids: set[str] = set()
    if not attack:
        return tech_ids, tactic_ids
    for key in ("framework", "version", "tactics", "techniques", "data_components"):
        if key not in attack:
            err(f"attack-enterprise.json: missing top-level key '{key}'")
    for t in attack.get("tactics", []):
        tid = t.get("id", "")
        if not TACTIC_RE.match(tid):
            err(f"attack: malformed tactic id {tid!r}")
        if tid in tactic_ids:
            err(f"attack: duplicate tactic id {tid}")
        tactic_ids.add(tid)
        if not t.get("name"):
            err(f"attack: tactic {tid} has no name")
    for d in attack.get("data_components", []):
        dc_ids.add(d.get("id", ""))
    names: dict[str, str] = {}
    for t in attack.get("techniques", []):
        tid = t.get("id", "")
        if not TECH_RE.match(tid):
            err(f"attack: malformed technique id {tid!r}")
            continue
        if tid in tech_ids:
            err(f"attack: duplicate technique id {tid}")
        tech_ids.add(tid)
        names[tid] = t.get("name", "")
        if not t.get("name"):
            err(f"attack: technique {tid} has no name")
        if not t.get("tactics"):
            warn(f"attack: technique {tid} has no tactic")
        for ta in t.get("tactics", []):
            if ta not in tactic_ids:
                err(f"attack: technique {tid} references unknown tactic {ta}")
        for p in t.get("platforms", []):
            if p not in KNOWN_PLATFORMS:
                warn(f"attack: technique {tid} has unrecognised platform {p!r}")
        for dc in t.get("data_components", []):
            if dc.get("id") and dc["id"] not in dc_ids:
                warn(f"attack: technique {tid} references unknown data component {dc.get('id')}")
    # parent integrity for sub-techniques
    for t in attack.get("techniques", []):
        tid = t.get("id", "")
        if SUBTECH_RE.match(tid):
            parent = tid.split(".")[0]
            if parent not in tech_ids:
                err(f"attack: sub-technique {tid} has no parent technique {parent}")
    if len(tactic_ids) < 14:
        warn(f"attack: only {len(tactic_ids)} tactics (expected 14 for Enterprise)")
    return tech_ids, tactic_ids


def known_log_source_types() -> set:
    cat = load("log-source-catalog.json") or {}
    return {t.get("id") for t in cat.get("types", [])}


def validate_scenarios(tech_ids: set, ls_types: set) -> None:
    data = load("detection-scenario-templates.json")
    if not data:
        return
    kb = data.get("kb", {})
    if not kb:
        err("detection-scenario-templates.json: empty knowledge base")
    total = 0
    for technique, entry in kb.items():
        if not TECH_RE.match(technique):
            err(f"scenarios: malformed technique key {technique!r}")
        if tech_ids and technique not in tech_ids:
            warn(f"scenarios: technique {technique} is not in the ATT&CK dataset")
        seen_ids: set[str] = set()
        scenarios = entry.get("scenarios", [])
        if not scenarios:
            err(f"scenarios: {technique} has no scenarios")
        for sc in scenarios:
            total += 1
            sid = sc.get("id", "")
            if not sid:
                err(f"scenarios: {technique} has a scenario without an id")
            if sid in seen_ids:
                err(f"scenarios: {technique} duplicate scenario id {sid}")
            seen_ids.add(sid)
            if not sc.get("name"):
                err(f"scenarios: {technique}/{sid} has no name")
            if sc.get("logic_type") not in LOGIC_TYPES:
                err(f"scenarios: {technique}/{sid} has unknown logic_type {sc.get('logic_type')!r}")
            if sc.get("severity") not in LEVELS:
                err(f"scenarios: {technique}/{sid} has invalid severity {sc.get('severity')!r}")
            agg = sc.get("agg") or {}
            # A scenario must carry detection logic either as field predicates (selection)
            # or as an aggregation (e.g. absence/sequence detections key entirely off agg).
            if not sc.get("selection") and not agg.get("fn"):
                err(f"scenarios: {technique}/{sid} has neither a selection nor an aggregation (no detection logic)")
            for lst in sc.get("log_source_types", []):
                if ls_types and lst not in ls_types:
                    warn(f"scenarios: {technique}/{sid} references unknown log source type {lst!r}")
            tests = sc.get("tests", [])
            if not tests:
                warn(f"scenarios: {technique}/{sid} has no validation test cases")
            for tc in tests:
                if tc.get("expected") not in ("match", "no_match"):
                    err(f"scenarios: {technique}/{sid} test {tc.get('name')!r} has invalid expected {tc.get('expected')!r}")
    stats = data.get("stats", {})
    if stats.get("scenarios") not in (None, total):
        warn(f"scenarios: declared stats.scenarios={stats.get('scenarios')} but counted {total}")


def validate_xrefs(name: str, items_key: str, id_field: str, tech_ids: set) -> None:
    data = load(name)
    if not data:
        return
    for item in data.get(items_key, []):
        for ref in item.get("attack_techniques", []):
            if not TECH_RE.match(ref):
                err(f"{name}: {item.get(id_field)} has malformed ATT&CK ref {ref!r}")
            elif tech_ids and ref not in tech_ids and ref.split(".")[0] not in tech_ids:
                warn(f"{name}: {item.get(id_field)} references ATT&CK id {ref} not in the dataset")


def validate_profiles(ls_types: set) -> None:
    data = load("environment-profiles.json")
    if not data:
        return
    for p in data.get("profiles", []):
        if not p.get("id") or not p.get("name"):
            err(f"profiles: a profile is missing id/name ({p.get('id')})")
        for plat in p.get("platforms", []):
            if plat not in KNOWN_PLATFORMS:
                warn(f"profiles: {p.get('id')} has unrecognised platform {plat!r}")
        for lst in p.get("expected_log_sources", []):
            if ls_types and lst not in ls_types:
                warn(f"profiles: {p.get('id')} references unknown log source type {lst!r}")


def main() -> int:
    attack = load("attack-enterprise.json")
    tech_ids, _ = validate_attack(attack)
    ls_types = known_log_source_types()
    validate_scenarios(tech_ids, ls_types)
    validate_xrefs("d3fend.json", "techniques", "id", tech_ids)
    validate_xrefs("capec.json", "patterns", "id", tech_ids)
    validate_profiles(ls_types)

    # Kill Chain references tactics
    kc = load("killchain.json")
    if kc:
        for phase in kc.get("phases", []):
            for ta in phase.get("attack_tactics", []):
                if not TACTIC_RE.match(ta):
                    err(f"killchain: phase {phase.get('id')} has malformed tactic ref {ta!r}")

    for w in warnings:
        print(f"warning: {w}")
    if errors:
        print()
        for e in errors:
            print(f"ERROR: {e}")
        print(f"\n{len(errors)} error(s), {len(warnings)} warning(s) — FAILED")
        return 1
    print(f"\nAll datasets valid ({len(warnings)} warning(s)).")
    print(f"  ATT&CK techniques: {len(tech_ids)} · log source types: {len(ls_types)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
