/* SENTINEL MATRIX — detection scenario knowledge base (deterministic, template-driven; no AI model).
   Each scenario is a DEFENSIVE detection specification: data source, event IDs, field conditions, aggregation,
   false-positive notes, tuning guidance, and validation test expectations. The generator renders these to
   Sigma / SPL / KQL / ES|QL / QRadar specifications. Conditions describe what the DEFENDER monitors; they are
   intentionally expressed as telemetry field predicates, not as attacker command payloads. */
(function (SM) {
  'use strict';
  const S = (id, name, objective, logic_type, o) => Object.assign({ id, name, objective, logic_type, severity: 'medium', keywords: [], event_ids: [], log_source_types: [], selection: [], exclusions: [], agg: null, fp: [], tuning: [], tests: [] }, o);
  const eq = (field, value) => ({ field, op: Array.isArray(value) ? 'in' : 'eq', value });
  const contains = (field, value) => ({ field, op: Array.isArray(value) ? 'contains_any' : 'contains', value });
  const ends = (field, value) => ({ field, op: Array.isArray(value) ? 'endswith_any' : 'endswith', value });
  const ne = (field, value) => ({ field, op: 'ne', value });
  const not_in = (field, value) => ({ field, op: 'not_in', value });
  const agg = (fn, group_by, threshold, window_minutes, extra) => Object.assign({ fn, group_by, threshold, window_minutes }, extra || {});
  const T = (name, input, expected) => ({ name, input, expected });
  const WS = ['windows_security'], SY = ['sysmon', 'edr'], PS = ['powershell'], DC = ['active_directory', 'windows_security'], LX = ['linux_auditd'], NET = ['firewall', 'proxy', 'netflow'], DNS = ['dns'];

  // The scenario library is a bundled JSON dataset (data/detection-scenario-templates.json),
  // loaded here and merged with any analyst-authored templates persisted in IndexedDB.
  let KB = {};
  SM.Scenarios = {
    get KB() { return KB; },
    async init() {
      const bundled = (SM.FW && SM.FW.readBundled('scenarios')) || (SM.BUNDLED && SM.BUNDLED.scenarios) || null;
      if (bundled && bundled.kb) KB = SM.deepClone(bundled.kb);
      try { const custom = await SM.DB.getAll('scenario_templates'); for (const row of custom) { if (!row.technique || !row.scenario) continue; if (!KB[row.technique]) KB[row.technique] = { name: row.technique_name || row.technique, scenarios: [] }; const idx = KB[row.technique].scenarios.findIndex(s => s.id === row.scenario.id); if (idx >= 0) KB[row.technique].scenarios[idx] = row.scenario; else KB[row.technique].scenarios.push(row.scenario); } } catch (e) { /* DB may be unavailable in tests */ }
      SM.emit('scenarios:loaded');
    },
    get(techId) { return KB[techId] || KB[SM.parentTechnique(techId)] || null; },
    has(techId) { return !!(KB[techId] || KB[SM.parentTechnique(techId)]); },
    register(map) { Object.assign(KB, map); return SM.Scenarios; },
    async addCustom(technique, techniqueName, scenario) { scenario.id = scenario.id || ('CUST-' + SM.hash(technique + scenario.name).slice(0, 5).toUpperCase()); scenario.custom = true; await SM.DB.put('scenario_templates', { id: technique + '::' + scenario.id, technique, technique_name: techniqueName, scenario }); if (!KB[technique]) KB[technique] = { name: techniqueName || technique, scenarios: [] }; const i = KB[technique].scenarios.findIndex(s => s.id === scenario.id); if (i >= 0) KB[technique].scenarios[i] = scenario; else KB[technique].scenarios.push(scenario); return scenario; },
    S, eq, contains, ends, ne, not_in, agg, T, groups: { WS, SY, PS, DC, LX, NET, DNS },
    all() { return Object.entries(KB).map(([technique, v]) => ({ technique, name: v.name, scenarios: v.scenarios })); },
    forCoverage() { const o = {}; for (const [t, v] of Object.entries(KB)) o[t] = v; return o; },
    count() { return Object.values(KB).reduce((a, v) => a + v.scenarios.length, 0); },
    techniqueCount() { return Object.keys(KB).length; }
  };
})(globalThis.SM = globalThis.SM || {});
