/* SENTINEL MATRIX — gap analysis, rule quality/effectiveness, prioritisation. */
(function (SM) {
  'use strict';

  // ---------------- Rule quality & effectiveness ----------------
  const QUAL = {};
  QUAL.DEFAULT_WEIGHTS = { logic: 20, telemetry: 15, mapping: 15, scenario: 15, operational: 10, validation: 10, configuration: 10, tuning: 5 };
  QUAL.assess = (rule, ctx = {}) => {
    const w = ctx.weights || QUAL.DEFAULT_WEIGHTS; const tel = ctx.telemetry; const stats = (ctx.alertStats && ctx.alertStats[rule.rule_id]) || {}; const tests = (ctx.testsByRule && ctx.testsByRule[rule.rule_id]) || [];
    const c = {};
    // logic completeness
    let logic = 0; const dl = SM.str(rule.detection_logic); if (dl.length > 12) logic += 35; if (dl.length > 120) logic += 15; if (rule.event_fields.length >= 2) logic += 15; if (rule.threshold || rule.time_window || rule.grouping_fields.length) logic += 20; if (rule.conditions.length || /\b(and|or|not|by|where)\b/i.test(dl)) logic += 15; c.logic = Math.min(100, logic);
    // telemetry availability
    if (tel && tel.known && rule.log_source_types.length) { const st = SM.Coverage.ruleTelemetryStatus(rule, tel); c.telemetry = st === 'available' ? 100 : st === 'partial' ? 55 : st === 'unknown' ? 40 : 10; } else c.telemetry = rule.log_source_types.length ? 50 : 15;
    // mapping accuracy
    c.mapping = !rule.attack_techniques.length ? 0 : (rule.mapping_source.startsWith('explicit') ? 100 : (rule.mapping_source === 'text-reference' ? 80 : (rule.mapping_source === 'inferred' ? 40 : 60)));
    // scenario diversity (vs the technique's known scenarios, and against sibling rules)
    let scenario = 50; if (ctx.scenarioCoverageForRule) scenario = ctx.scenarioCoverageForRule(rule); c.scenario = scenario;
    // operational status
    c.operational = rule.enabled_status === 'enabled' ? (stats.alerts ? 100 : 60) : (rule.enabled_status === 'disabled' ? 10 : 40);
    // validation evidence
    const passed = tests.filter(t => t.status === 'PASS').length, failed = tests.filter(t => t.status === 'FAIL').length; c.validation = tests.length ? Math.round(100 * passed / tests.length) - (failed ? 20 : 0) : 0; c.validation = SM.clamp(c.validation, 0, 100);
    // configuration quality
    let cfg = 40; if (rule.severity !== 'unknown') cfg += 15; if (rule.description) cfg += 15; if (rule.false_positive_notes) cfg += 15; if (rule.suppression_conditions.length || rule.entity_context.length) cfg += 15; c.configuration = Math.min(100, cfg);
    // tuning quality
    let tun = 0; if (rule.false_positive_notes) tun += 50; if (stats.alerts !== undefined && stats.alerts < (stats.observation_days ? stats.observation_days * 50 : 5000)) tun += 25; if (rule.suppression_conditions.length) tun += 25; c.tuning = Math.min(100, tun || (rule.false_positive_notes ? 50 : 20));
    const tot = Object.values(w).reduce((a, b) => a + b, 0) || 1;
    const score = Math.round(Object.entries(w).reduce((a, [k, v]) => a + (c[k] || 0) * v, 0) / tot);
    const grade = score >= 80 ? 'A' : score >= 65 ? 'B' : score >= 50 ? 'C' : score >= 35 ? 'D' : 'E';
    return { rule_id: rule.rule_id, score, grade, components: c, weights: w, notes: QUAL.notes(rule, c, stats, tests) };
  };
  QUAL.notes = (rule, c, stats, tests) => { const n = []; if (c.logic < 40) n.push('Detection logic is thin or missing.'); if (c.mapping === 0) n.push('No ATT&CK mapping.'); else if (rule.mapping_source === 'inferred') n.push('Mapping is inferred from keywords — confirm manually.'); if (c.telemetry <= 10) n.push('Required log sources are not present in the inventory.'); if (!tests.length) n.push('No validation evidence (rule never tested).'); if (rule.enabled_status === 'disabled') n.push('Rule is disabled.'); if (rule.enabled_status === 'enabled' && stats.alerts === 0 && stats.observation_days) n.push('Enabled but has not triggered in ' + stats.observation_days + ' days — assess expected frequency before judging effectiveness.'); if (stats.alerts && stats.observation_days && stats.alerts / stats.observation_days > 500) n.push('Very high alert volume (' + Math.round(stats.alerts / stats.observation_days) + '/day) — likely needs tuning.'); return n; };
  QUAL.effectiveness = (rule, ctx = {}) => {
    // Classify operational effectiveness without punishing never-triggered rules unfairly.
    const stats = (ctx.alertStats && ctx.alertStats[rule.rule_id]) || {}; const days = stats.observation_days || ctx.observationDays || 0; const alerts = stats.alerts || 0; const offenses = stats.offenses || 0; const fp = stats.false_positives || 0;
    const flags = [];
    if (rule.enabled_status === 'enabled') { if (days && alerts === 0) flags.push({ k: 'never_triggered', sev: 'info', text: 'Enabled but no alerts in ' + days + ' days. This is only a concern if the technique is expected to occur and telemetry is present.' }); if (days && alerts / days > 500) flags.push({ k: 'excessive', sev: 'high', text: 'Excessive alerting (~' + Math.round(alerts / days) + '/day).' }); if (offenses && alerts && offenses / alerts > 0.8 && alerts > 20) flags.push({ k: 'offense_storm', sev: 'high', text: 'Most alerts become offenses — recurring offense source.' }); if (fp && alerts && fp / alerts > 0.5) flags.push({ k: 'high_fp', sev: 'medium', text: 'High false-positive ratio (' + Math.round(100 * fp / alerts) + '%).' }); }
    if (rule.log_source_types.length && ctx.telemetry && ctx.telemetry.known && SM.Coverage.ruleTelemetryStatus(rule, ctx.telemetry) === 'missing') flags.push({ k: 'no_telemetry', sev: 'high', text: 'Rule has no supporting telemetry — cannot fire regardless of activity.' });
    if (rule.log_source_types.length && ctx.staleLogSources && rule.log_source_types.some(t => ctx.staleLogSources.has(t))) flags.push({ k: 'stale_source', sev: 'medium', text: 'Depends on a log source that is stale/inactive.' });
    return { rule_id: rule.rule_id, flags, alerts, offenses, days };
  };

  // ---------------- Gap analysis ----------------
  const GAP = {};
  GAP.DEFAULT_WEIGHTS = { technique_importance: 20, threat_relevance: 20, asset_criticality: 20, detection_weakness: 20, telemetry: 10, chain_position: 10 };
  // Importance by tactic (relative, configurable). Higher = more impactful to miss.
  GAP.TACTIC_IMPORTANCE = { TA0006: 95, TA0004: 90, TA0003: 80, TA0008: 90, TA0005: 85, TA0002: 80, TA0040: 95, TA0010: 85, TA0001: 85, TA0011: 80, TA0009: 60, TA0007: 55, TA0043: 35, TA0042: 35 };

  GAP.analyse = (coverageResults, ctx = {}) => {
    const w = ctx.weights || GAP.DEFAULT_WEIGHTS; const assets = ctx.assets || []; const tel = ctx.telemetry; const intelByTech = ctx.intel || null; const telemetryFor = ctx.telemetryFor || (() => ({ logSourceTypes: [] }));
    const gaps = [];
    const critAssets = assets.filter(a => /crit|high/i.test(SM.str(a.criticality)));
    for (const r of coverageResults) {
      if (['VALIDATED', 'FULLY_COVERED', 'NOT_APPLICABLE'].includes(r.classification)) continue;
      const t = SM.FW && SM.FW.technique(r.technique_id); const req = telemetryFor(r.technique_id);
      const importance = Math.max(0, ...(r.tactics || []).map(x => GAP.TACTIC_IMPORTANCE[x] || 50));
      // threat relevance: ONLY from imported intel; otherwise unknown
      let threatRel = null, threatRelKnown = false; if (intelByTech && intelByTech[r.technique_id] !== undefined) { threatRel = intelByTech[r.technique_id]; threatRelKnown = true; } else if (intelByTech && intelByTech[SM.parentTechnique(r.technique_id)] !== undefined) { threatRel = intelByTech[SM.parentTechnique(r.technique_id)]; threatRelKnown = true; }
      const weaknessMap = { NOT_COVERED: 100, WEAK_COVERAGE: 75, UNVALIDATED_COVERAGE: 55, PARTIALLY_COVERED: 45, UNKNOWN: 60 };
      const weakness = weaknessMap[r.classification] || 50;
      const telGap = tel && tel.known && (req.logSourceTypes || []).length ? Math.round(100 * (r.missing_log_source_types || []).length / req.logSourceTypes.length) : (req.logSourceTypes && req.logSourceTypes.length ? 50 : 30);
      // asset criticality exposure: applicable critical assets in zones lacking telemetry
      const plats = (t && t.platforms || []).filter(p => p !== 'PRE');
      const exposedAssets = critAssets.filter(a => !plats.length || plats.includes(SM.Coverage.assetPlatform(a.os)));
      const assetCrit = assets.length ? Math.round(100 * Math.min(1, exposedAssets.length / Math.max(1, critAssets.length || 1))) * (exposedAssets.length ? 1 : 0.3) : 40;
      const chainPos = GAP.chainPosition(r.tactics);
      const dims = { technique_importance: importance, threat_relevance: threatRelKnown ? threatRel : 50, asset_criticality: assetCrit, detection_weakness: weakness, telemetry: telGap, chain_position: chainPos };
      const tot = Object.values(w).reduce((a, b) => a + b, 0) || 1;
      const priority = Math.round(Object.entries(w).reduce((a, [k, v]) => a + (dims[k] || 0) * v, 0) / tot);
      const scenarios = SM.Scenarios && SM.Scenarios.get(r.technique_id);
      const gap = {
        gap_id: 'GAP-' + r.technique_id, technique_id: r.technique_id, technique_name: r.technique_name, technique_description: t && t.description, tactics: r.tactics,
        current_coverage: r.classification, confidence: r.confidence, existing_rule_ids: r.rule_ids,
        missing_scenarios: scenarios ? (r.scenarios_missing && r.scenarios_missing.length ? r.scenarios_missing : scenarios.scenarios.filter(s => !(r.scenarios_matched || []).includes(s.id)).map(s => s.id)) : [],
        known_scenario_count: scenarios ? scenarios.scenarios.length : 0,
        required_telemetry: req.logSourceTypes || [], available_telemetry: (req.logSourceTypes || []).filter(x => tel && tel.available && tel.available.has(x)), missing_telemetry: r.missing_log_source_types || [],
        business_impact: GAP.impactText(importance, r.tactics), asset_exposure: { critical_assets_applicable: exposedAssets.length, zones_without_telemetry: r.zones_without_telemetry || [] },
        risk_level: priority >= 75 ? 'critical' : priority >= 55 ? 'high' : priority >= 35 ? 'medium' : 'low',
        priority_score: priority, priority_dimensions: dims, threat_relevance_known: threatRelKnown,
        recommended_action: GAP.recommend(r, scenarios, telGap), proposed_rule_available: !!scenarios,
        validation_requirements: scenarios ? 'Execute the ' + (scenarios.scenarios.reduce((a, s) => a + (s.tests ? s.tests.length : 0), 0)) + ' bundled test cases in the Validation Workbench before marking covered.' : 'Author detection logic and define PASS/FAIL test cases.',
        status: 'open', created_at: SM.now()
      };
      if (!threatRelKnown) gap.threat_relevance_note = 'Threat-intelligence relevance is UNKNOWN — no threat intelligence dataset has been imported. Priority uses a neutral placeholder for this dimension.';
      gaps.push(gap);
    }
    gaps.sort((a, b) => b.priority_score - a.priority_score);
    return { gaps, generated_at: SM.now(), weights: w, intel_loaded: !!intelByTech, summary: { total: gaps.length, critical: gaps.filter(g => g.risk_level === 'critical').length, high: gaps.filter(g => g.risk_level === 'high').length, medium: gaps.filter(g => g.risk_level === 'medium').length, low: gaps.filter(g => g.risk_level === 'low').length, with_proposals: gaps.filter(g => g.proposed_rule_available).length } };
  };
  GAP.chainPosition = (tactics) => { const early = ['TA0043', 'TA0042', 'TA0001', 'TA0002']; const mid = ['TA0003', 'TA0004', 'TA0005', 'TA0006', 'TA0007', 'TA0008']; const late = ['TA0009', 'TA0011', 'TA0010', 'TA0040']; if ((tactics || []).some(t => mid.includes(t))) return 80; if ((tactics || []).some(t => late.includes(t))) return 70; if ((tactics || []).some(t => early.includes(t))) return 55; return 50; };
  GAP.impactText = (imp, tactics) => { const names = (tactics || []).map(t => SM.FW ? SM.FW.tacticName(t) : t).join(', '); return (imp >= 85 ? 'High-impact adversary objective' : imp >= 60 ? 'Moderate-impact adversary objective' : 'Lower-impact / early-stage activity') + (names ? ' (' + names + ')' : '') + '. Missing or weak detection here ' + (imp >= 85 ? 'materially increases breach risk.' : 'reduces defence-in-depth.'); };
  GAP.recommend = (r, scenarios, telGap) => { const a = []; if (r.classification === 'NOT_COVERED') a.push(scenarios ? 'Generate and deploy detection rules from the ' + scenarios.scenarios.length + ' bundled scenarios.' : 'Engineer new detection logic for this technique.'); if (r.classification === 'WEAK_COVERAGE') { if ((r.rule_states || []).every(s => !s.enabled)) a.push('Enable the existing mapped rule(s) after review.'); if ((r.rule_states || []).some(s => s.inferred)) a.push('Confirm the inferred ATT&CK mapping and make it explicit.'); } if (telGap > 0) a.push('Onboard missing telemetry: ' + (r.missing_log_source_types || []).join(', ') + '.'); if (r.classification === 'PARTIALLY_COVERED' && scenarios) a.push('Add detection scenarios for the uncovered variants.'); if (r.classification === 'UNVALIDATED_COVERAGE') a.push('Validate existing rules with executed test cases.'); if (!a.length) a.push('Review and strengthen existing detection.'); return a; };

  SM.Quality = QUAL; SM.Gaps = GAP;
})(globalThis.SM = globalThis.SM || {});
