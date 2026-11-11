/* SENTINEL MATRIX — ATT&CK coverage engine (pure; runs in main thread or Web Worker). */
(function (SM) {
  'use strict';
  const COV = {};
  COV.DEFAULT_WEIGHTS = { mapping: 15, configured: 20, operational: 20, validated: 20, telemetry: 15, asset: 10 };
  COV.DEFAULT_THRESHOLDS = { scenarioFull: 0.6, minRulesFull: 2, minQualityFull: 55 };

  // Minimal per-rule quality used by coverage (full assessment in Quality engine)
  COV.ruleBaseQuality = (r) => { let q = 0; if (r.detection_logic && r.detection_logic.length > 20) q += 30; if (r.attack_techniques.length && r.mapping_source.startsWith('explicit')) q += 20; else if (r.attack_techniques.length) q += 8; if (r.log_source_types.length) q += 15; if (r.event_fields.length >= 2) q += 10; if (r.description) q += 10; if (r.threshold || r.time_window || r.grouping_fields.length) q += 10; if (r.false_positive_notes) q += 5; return q; };

  // Telemetry availability: log source types present with healthy status in inventory
  COV.availableTelemetry = (logSources) => { const avail = new Set(), degraded = new Set(), zonesByType = {}; for (const ls of logSources || []) { const t = ls.source_type; if (!t) continue; if (ls.health_status === 'healthy' || ls.collection_status === 'active') avail.add(t); else degraded.add(t); if (ls.zone) { (zonesByType[t] = zonesByType[t] || new Set()).add(ls.zone); } } for (const t of avail) degraded.delete(t); return { available: avail, degraded, zonesByType, known: (logSources || []).length > 0 }; };

  COV.ruleTelemetryStatus = (rule, tel) => { if (!tel.known) return 'unknown'; const needs = rule.log_source_types || []; if (!needs.length) return 'unknown'; const have = needs.filter(t => tel.available.has(t)); if (have.length === needs.length) return 'available'; if (have.length || needs.some(t => tel.degraded.has(t))) return 'partial'; return 'missing'; };

  COV.assess = (input) => {
    const { rules = [], techniques = [], logSources = [], tests = [], profile = null, assets = [], scenarioKB = {}, weights = COV.DEFAULT_WEIGHTS, thresholds = COV.DEFAULT_THRESHOLDS, telemetryFor = () => ({ logSourceTypes: [] }), alertStats = {} } = input;
    const tel = COV.availableTelemetry(logSources);
    const byTech = new Map(); const byParent = new Map();
    for (const r of rules) for (const t of r.attack_techniques || []) { (byTech.get(t) || byTech.set(t, []).get(t)).push(r); const p = t.split('.')[0]; if (p !== t) (byParent.get(p) || byParent.set(p, []).get(p)).push(r); }
    const passedRules = new Set(tests.filter(t => t.status === 'PASS').map(t => t.rule_id));
    const failedRules = new Set(tests.filter(t => t.status === 'FAIL').map(t => t.rule_id));
    const profilePlatforms = profile ? new Set(profile.platforms || []) : null;
    const zoneAssets = {}; for (const a of assets) { const z = a.zone || 'Unassigned'; (zoneAssets[z] = zoneAssets[z] || { platforms: new Set(), count: 0 }).platforms.add(COV.assetPlatform(a.os)); zoneAssets[z].count++; }
    const results = [];
    for (const tech of techniques) {
      const direct = byTech.get(tech.id) || []; const viaSub = tech.is_subtechnique ? [] : (byParent.get(tech.id) || []).filter(r => !direct.includes(r));
      const allRules = SM.uniq([...direct, ...viaSub]);
      const req = telemetryFor(tech.id); const reqTypes = req.logSourceTypes || [];
      const r = { technique_id: tech.id, technique_name: tech.name, tactics: tech.tactics, is_subtechnique: !!tech.is_subtechnique, rule_ids: allRules.map(x => x.rule_id), direct_rule_ids: direct.map(x => x.rule_id), subtechnique_rule_ids: viaSub.map(x => x.rule_id), classification: 'UNKNOWN', confidence: 'low', dimensions: { mapping: 0, configured: 0, operational: 0, validated: 0, telemetry: 0, asset: 0 }, required_log_source_types: reqTypes, missing_log_source_types: [], degraded_log_source_types: [], scenario_coverage: null, scenarios_matched: [], scenarios_missing: [], reasons: [], rule_states: [], assessed_at: new Date().toISOString() };
      // Not applicable
      const plats = (tech.platforms || []).filter(p => p !== 'PRE');
      if (profilePlatforms && plats.length && !plats.some(p => profilePlatforms.has(p))) { r.classification = 'NOT_APPLICABLE'; r.reasons.push('Technique platforms (' + plats.join(', ') + ') are outside the active environment profile.'); results.push(r); continue; }
      // telemetry dimension
      if (tel.known && reqTypes.length) { const have = reqTypes.filter(t => tel.available.has(t)); r.missing_log_source_types = reqTypes.filter(t => !tel.available.has(t) && !tel.degraded.has(t)); r.degraded_log_source_types = reqTypes.filter(t => tel.degraded.has(t)); r.dimensions.telemetry = Math.round(100 * (have.length + 0.5 * r.degraded_log_source_types.length) / reqTypes.length); }
      else if (!reqTypes.length) { r.dimensions.telemetry = 50; r.reasons.push('No telemetry requirements defined for this technique in the framework dataset.'); }
      else { r.dimensions.telemetry = 0; r.reasons.push('Log source inventory not loaded; telemetry availability unknown.'); }
      // scenario coverage
      const kb = scenarioKB[tech.id] || null;
      if (kb && kb.scenarios && kb.scenarios.length) { const matched = []; const missing = []; for (const sc of kb.scenarios) { const hit = allRules.some(rule => COV.ruleMatchesScenario(rule, sc)); (hit ? matched : missing).push(sc.id); } r.scenarios_matched = matched; r.scenarios_missing = missing; r.scenario_coverage = matched.length / kb.scenarios.length; }
      if (!allRules.length) { r.classification = 'NOT_COVERED'; r.reasons.push('No imported rule maps to this technique' + (tech.is_subtechnique ? '.' : ' or its sub-techniques.')); r.confidence = tel.known ? 'high' : 'medium'; r.dimensions.asset = 0; results.push(r); continue; }
      // rule states
      const states = allRules.map(rule => { const telemetry = COV.ruleTelemetryStatus(rule, tel); const quality = COV.ruleBaseQuality(rule); const stats = alertStats[rule.rule_id] || {}; return { rule_id: rule.rule_id, enabled: rule.enabled_status === 'enabled', unknownState: rule.enabled_status === 'unknown', telemetry, quality, explicit: rule.mapping_source.startsWith('explicit') || rule.mapping_source === 'text-reference', inferred: rule.mapping_source === 'inferred', validated: passedRules.has(rule.rule_id), failed: failedRules.has(rule.rule_id), triggered: (stats.alerts || 0) > 0 || !!rule.last_triggered, viaSub: viaSub.includes(rule) }; });
      r.rule_states = states;
      const enabled = states.filter(s => s.enabled || s.unknownState); const strong = enabled.filter(s => s.telemetry === 'available' && s.quality >= thresholds.minQualityFull && !s.inferred);
      const anyExplicit = states.some(s => s.explicit); const anyEnabled = enabled.length > 0; const anyTelOk = enabled.some(s => s.telemetry === 'available' || s.telemetry === 'partial'); const anyTelUnknown = enabled.some(s => s.telemetry === 'unknown'); const anyValidated = states.some(s => s.validated && (s.enabled || s.unknownState));
      const distinctLogic = SM.uniq(allRules.map(x => x.fingerprint)).length;
      // dimensions
      r.dimensions.mapping = anyExplicit ? 100 : 50; if (!direct.length && viaSub.length) r.dimensions.mapping = Math.min(r.dimensions.mapping, 70);
      r.dimensions.configured = anyEnabled ? Math.round(Math.min(100, 40 + 0.6 * Math.max(...enabled.map(s => s.quality)))) : 10;
      r.dimensions.operational = anyEnabled ? Math.round((anyTelOk ? 60 : anyTelUnknown ? 35 : 10) + (enabled.some(s => s.triggered) ? 25 : 0) + (strong.length ? 15 : 0)) : 0;
      r.dimensions.validated = anyValidated ? 100 : (states.some(s => s.failed) ? 10 : 0);
      // asset coverage: proportion of zones (with assets of applicable platforms) where at least one required log source type is collected
      const appZones = Object.entries(zoneAssets).filter(([, v]) => !plats.length || plats.some(p => v.platforms.has(p))); if (appZones.length && reqTypes.length) { const okZones = appZones.filter(([z]) => reqTypes.some(t => tel.zonesByType[t] && tel.zonesByType[t].has(z))); r.dimensions.asset = Math.round(100 * okZones.length / appZones.length); r.zones_without_telemetry = appZones.filter(([z]) => !okZones.some(([oz]) => oz === z)).map(([z]) => z); } else r.dimensions.asset = assets.length ? 50 : 0;
      // classification
      if (anyValidated && anyEnabled && anyTelOk) { r.classification = 'VALIDATED'; r.reasons.push('An enabled, telemetry-backed rule has passed an executed validation test.'); r.confidence = 'high'; }
      else if (!anyEnabled) { r.classification = 'WEAK_COVERAGE'; r.reasons.push('All mapped rules are disabled.'); r.confidence = 'high'; }
      else if (!anyExplicit) { r.classification = 'WEAK_COVERAGE'; r.reasons.push('Mappings to this technique are inferred from keywords only; treat as unconfirmed.'); r.confidence = 'low'; }
      else if (enabled.every(s => s.telemetry === 'missing')) { r.classification = 'WEAK_COVERAGE'; r.reasons.push('Rules are enabled but required log sources are not present in the inventory.'); r.confidence = 'medium'; }
      else if (!anyTelOk && anyTelUnknown) { r.classification = 'UNVALIDATED_COVERAGE'; r.reasons.push('Rules are enabled but telemetry availability could not be determined (no log source inventory or rule declares no log source).'); r.confidence = 'low'; }
      else if (enabled.every(s => s.quality < thresholds.minQualityFull)) { r.classification = 'WEAK_COVERAGE'; r.reasons.push('Mapped rules have low logic completeness (thin or missing detection logic).'); r.confidence = 'medium'; }
      else {
        const scenOK = r.scenario_coverage === null ? (distinctLogic >= thresholds.minRulesFull) : r.scenario_coverage >= thresholds.scenarioFull;
        const multi = distinctLogic >= thresholds.minRulesFull || (r.scenario_coverage !== null && r.scenario_coverage >= thresholds.scenarioFull);
        if (strong.length && scenOK && multi && direct.length) { r.classification = 'FULLY_COVERED'; r.reasons.push('Enabled rules with available telemetry cover the principal detection scenarios (' + (r.scenario_coverage === null ? distinctLogic + ' distinct detection logics' : Math.round(r.scenario_coverage * 100) + '% of known scenarios') + ').'); r.confidence = 'medium'; }
        else { r.classification = 'PARTIALLY_COVERED'; if (!direct.length) r.reasons.push('Coverage is only via sub-technique rules; the parent has no direct rule.'); if (r.scenario_coverage !== null && r.scenario_coverage < thresholds.scenarioFull) r.reasons.push('Only ' + r.scenarios_matched.length + ' of ' + (r.scenarios_matched.length + r.scenarios_missing.length) + ' known detection scenarios are addressed.'); if (distinctLogic < thresholds.minRulesFull && r.scenario_coverage === null) r.reasons.push('Single detection logic; scenario diversity is low.'); if (!strong.length) r.reasons.push('No rule combines available telemetry with sufficient logic quality.'); r.confidence = 'medium'; }
      }
      if (states.some(s => s.failed) && r.classification !== 'VALIDATED') r.reasons.push('At least one mapped rule FAILED a validation test.');
      r.composite = COV.composite(r.dimensions, weights);
      results.push(r);
    }
    return { results, summary: COV.summarise(results, techniques, weights), telemetry_known: tel.known, assessed_at: new Date().toISOString(), weights };
  };

  COV.ruleMatchesScenario = (rule, sc) => { const text = (rule.rule_name + ' ' + rule.description + ' ' + rule.detection_logic).toLowerCase(); const kw = (sc.keywords || []).map(k => k.toLowerCase()); if (!kw.length) return false; const hits = kw.filter(k => text.includes(k)).length; return hits >= Math.min(2, kw.length) || (hits >= 1 && sc.event_ids && sc.event_ids.some(e => (rule.event_ids || []).includes(e))); };
  COV.assetPlatform = (os) => { os = SM.str(os).toLowerCase(); if (/windows/.test(os)) return 'Windows'; if (/linux|ubuntu|rhel|centos|debian|suse/.test(os)) return 'Linux'; if (/mac|darwin/.test(os)) return 'macOS'; if (/ios|nx-?os|junos|aci|switch|router|firewall/.test(os)) return 'Network'; if (/cloud|aws|azure|gcp/.test(os)) return 'Cloud'; return 'Unknown'; };
  COV.composite = (d, w) => { const tot = Object.values(w).reduce((a, b) => a + b, 0) || 1; return Math.round(Object.entries(w).reduce((a, [k, v]) => a + (d[k] || 0) * v, 0) / tot); };

  COV.summarise = (results, techniques, weights) => {
    const applicable = results.filter(r => r.classification !== 'NOT_APPLICABLE');
    const counts = SM.countBy(results, 'classification');
    const dims = { mapping: 0, configured: 0, operational: 0, validated: 0, telemetry: 0, asset: 0 };
    if (applicable.length) for (const k of Object.keys(dims)) dims[k] = Math.round(SM.sum(applicable, r => r.dimensions[k] || 0) / applicable.length);
    const byTactic = {}; for (const r of results) for (const t of r.tactics || []) { const b = byTactic[t] = byTactic[t] || { total: 0, applicable: 0, covered: 0, partial: 0, weak: 0, none: 0, validated: 0 }; b.total++; if (r.classification === 'NOT_APPLICABLE') continue; b.applicable++; if (r.classification === 'VALIDATED') { b.validated++; b.covered++; } else if (r.classification === 'FULLY_COVERED') b.covered++; else if (r.classification === 'PARTIALLY_COVERED') b.partial++; else if (r.classification === 'WEAK_COVERAGE' || r.classification === 'UNVALIDATED_COVERAGE') b.weak++; else if (r.classification === 'NOT_COVERED') b.none++; }
    return { total: results.length, applicable: applicable.length, counts, dimensions: dims, composite: COV.composite(dims, weights), by_tactic: byTactic, parents: applicable.filter(r => !r.is_subtechnique).length, subtechniques: applicable.filter(r => r.is_subtechnique).length };
  };
  COV.explainScore = (dimKey) => ({ mapping: 'Mapping Coverage — share of applicable techniques with at least one rule mapped (explicit mappings score 100, inferred-only 50, sub-technique-only ≤70).', configured: 'Configured Coverage — mapped rules are enabled and their detection logic is complete enough to be meaningful.', operational: 'Operational Coverage — enabled rules whose required log sources are collected and which have produced alerts/offenses.', validated: 'Validated Coverage — techniques where a mapped rule has an executed PASS test case in the validation workbench.', telemetry: 'Telemetry Coverage — share of required data components (log source types) that are present and healthy in the log source inventory.', asset: 'Enterprise Asset Coverage — share of network zones containing applicable assets where the required telemetry is collected.' }[dimKey] || '');
  SM.Coverage = COV;
})(globalThis.SM = globalThis.SM || {});
