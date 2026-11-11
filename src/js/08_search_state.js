/* SENTINEL MATRIX — global search index, saved filters, and the central application state/store. */
(function (SM) {
  'use strict';

  // ---------------- Search index ----------------
  const SEARCH = { tokens: new Map(), docs: new Map() };
  const tokenize = (s) => SM.uniq(SM.str(s).toLowerCase().split(/[^a-z0-9.]+/).filter(x => x.length > 1));
  SEARCH.clear = () => { SEARCH.tokens.clear(); SEARCH.docs.clear(); };
  SEARCH.add = (doc) => { SEARCH.docs.set(doc.id, doc); for (const tk of tokenize(doc.text)) { if (!SEARCH.tokens.has(tk)) SEARCH.tokens.set(tk, new Set()); SEARCH.tokens.get(tk).add(doc.id); } };
  SEARCH.rebuild = (store) => {
    SEARCH.clear();
    for (const r of store.rules) SEARCH.add({ id: 'rule:' + r.rule_id, kind: 'rule', title: r.rule_name || r.rule_id, sub: r.source_platform + ' · ' + r.severity, ref: r.rule_id, text: [r.rule_id, r.rule_name, r.description, r.attack_techniques.join(' '), r.detection_logic, r.log_sources.join(' '), r.event_ids.join(' '), r.tags.join(' ')].join(' ') });
    for (const t of SM.FW.allTechniques()) SEARCH.add({ id: 'tech:' + t.id, kind: 'technique', title: t.id + ' ' + t.name, sub: (t.tactics || []).map(x => SM.FW.tacticName(x)).join(', '), ref: t.id, text: [t.id, t.name, t.description, (t.tactics || []).map(x => SM.FW.tacticName(x)).join(' ')].join(' ') });
    for (const g of store.gaps) SEARCH.add({ id: 'gap:' + g.gap_id, kind: 'gap', title: g.gap_id + ' ' + g.technique_name, sub: g.risk_level + ' · ' + g.current_coverage, ref: g.technique_id, text: [g.gap_id, g.technique_id, g.technique_name, g.recommended_action.join(' ')].join(' ') });
    for (const l of store.logSources) SEARCH.add({ id: 'ls:' + l.id, kind: 'log source', title: l.source_name || l.id, sub: l.source_type + ' · ' + l.health_status, ref: l.id, text: [l.id, l.source_name, l.source_type, l.hostname, l.zone].join(' ') });
    for (const a of store.assets) SEARCH.add({ id: 'asset:' + a.asset_id, kind: 'asset', title: a.hostname || a.asset_id, sub: a.zone + ' · ' + a.criticality, ref: a.asset_id, text: [a.asset_id, a.hostname, a.ip, a.os, a.zone, a.business_unit].join(' ') });
    for (const o of store.offenses) SEARCH.add({ id: 'off:' + o.id, kind: 'offense', title: o.description || ('Offense ' + o.id), sub: o.severity + ' · ' + o.status, ref: o.id, text: [o.id, o.description, o.status, (o.rule_ids || []).join(' ')].join(' ') });
    for (const sc of (SM.Scenarios ? SM.Scenarios.all() : [])) for (const s of sc.scenarios) SEARCH.add({ id: 'scn:' + sc.technique + ':' + s.id, kind: 'scenario', title: s.name, sub: sc.technique + ' · ' + s.logic_type, ref: sc.technique, text: [s.id, s.name, s.objective, sc.technique, (s.keywords || []).join(' ')].join(' ') });
  };
  SEARCH.query = (q, limit = 40) => { const toks = tokenize(q); if (!toks.length) return []; const score = new Map(); for (const tk of toks) { const exact = SEARCH.tokens.get(tk); const matches = exact ? [[tk, exact]] : Array.from(SEARCH.tokens.entries()).filter(([k]) => k.startsWith(tk)).slice(0, 50); for (const [, set] of matches) for (const id of set) score.set(id, (score.get(id) || 0) + 1); } const ranked = Array.from(score.entries()).map(([id, s]) => ({ doc: SEARCH.docs.get(id), score: s })).filter(x => x.doc).sort((a, b) => b.score - a.score || a.doc.title.length - b.doc.title.length); return ranked.slice(0, limit).map(x => x.doc); };
  SEARCH.filter = (rows, query) => { // advanced boolean filter: term, field:value, AND/OR/NOT, quotes
    if (!query || !query.trim()) return rows; const ast = parseQuery(query); return rows.filter(r => evalNode(ast, r)); };
  function parseQuery(q) { const tokens = q.match(/"[^"]*"|\(|\)|\S+/g) || []; let i = 0;
    const peek = () => tokens[i]; const next = () => tokens[i++];
    function parseOr() { let l = parseAnd(); while (peek() && /^or$/i.test(peek())) { next(); l = { op: 'or', l, r: parseAnd() }; } return l; }
    function parseAnd() { let l = parseNot(); while (peek() && !/^\)$/.test(peek()) && !/^or$/i.test(peek())) { if (/^and$/i.test(peek())) next(); l = { op: 'and', l, r: parseNot() }; } return l; }
    function parseNot() { if (peek() && /^(not|-)$/i.test(peek())) { next(); return { op: 'not', c: parseNot() }; } return parseAtom(); }
    function parseAtom() { const t = next(); if (t === '(') { const e = parseOr(); if (peek() === ')') next(); return e; } const m = SM.str(t).replace(/^"|"$/g, ''); const fm = m.match(/^([a-z_]+):(.*)$/i); return fm ? { op: 'field', field: fm[1].toLowerCase(), value: fm[2].toLowerCase() } : { op: 'term', value: m.toLowerCase() }; }
    return tokens.length ? parseOr() : { op: 'term', value: '' }; }
  function evalNode(n, row) { if (!n) return true; switch (n.op) { case 'and': return evalNode(n.l, row) && evalNode(n.r, row); case 'or': return evalNode(n.l, row) || evalNode(n.r, row); case 'not': return !evalNode(n.c, row); case 'field': { const v = SM.str(getField(row, n.field)).toLowerCase(); return v.includes(n.value); } case 'term': { if (!n.value) return true; return JSON.stringify(row).toLowerCase().includes(n.value); } default: return true; } }
  function getField(row, f) { const alias = { technique: 'attack_techniques', platform: 'source_platform', sev: 'severity', severity: 'severity', status: 'enabled_status', name: 'rule_name', logsource: 'log_source_types', mapping: 'mapping_source', lifecycle: 'lifecycle_stage' }; const key = alias[f] || f; const v = row[key]; return Array.isArray(v) ? v.join(' ') : (v === undefined ? (row[f] !== undefined ? row[f] : '') : v); }
  SM.Search = SEARCH;

  // ---------------- Central store ----------------
  const Store = {
    rules: [], logSources: [], assets: [], zones: [], offenses: [], alerts: [], generated: [], gaps: [], tests: [], reports: [], annotations: [], lifecycleEvents: [], savedFilters: [], auditRuns: [],
    coverage: null, gapAnalysis: null, settings: {}, activeProfileId: 'ad_enterprise', weights: { coverage: SM.Coverage.DEFAULT_WEIGHTS, quality: SM.Quality.DEFAULT_WEIGHTS, gap: SM.Gaps.DEFAULT_WEIGHTS }, filters: {}, intel: null,
    demoLoaded: false,

    async loadAll() {
      [this.rules, this.logSources, this.assets, this.offenses, this.alerts, this.generated, this.gaps, this.tests, this.reports, this.annotations, this.lifecycleEvents, this.savedFilters, this.auditRuns] =
        await Promise.all(['rules', 'log_sources', 'assets', 'offenses', 'alerts', 'generated_rules', 'gaps', 'validation_tests', 'reports', 'annotations', 'lifecycle_events', 'saved_filters', 'audit_runs'].map(s => SM.DB.getAll(s)));
      const cov = await SM.DB.getAll('coverage'); this.coverage = cov.length ? { results: cov, summary: SM.Coverage.summarise(cov, SM.FW.allTechniques(), this.weights.coverage), assessed_at: await SM.DB.setting('coverage_assessed_at'), weights: this.weights.coverage } : null;
      const settings = await SM.DB.getAll('settings'); this.settings = {}; for (const s of settings) this.settings[s.key] = s.value;
      this.activeProfileId = this.settings.active_profile || 'ad_enterprise';
      if (this.settings.weights_coverage) this.weights.coverage = this.settings.weights_coverage;
      if (this.settings.weights_quality) this.weights.quality = this.settings.weights_quality;
      if (this.settings.weights_gap) this.weights.gap = this.settings.weights_gap;
      this.demoLoaded = !!this.settings.demo_loaded;
      this.intel = this.settings.threat_intel || null;
      if (this.gaps.length) this.gapAnalysis = { gaps: this.gaps.sort((a, b) => b.priority_score - a.priority_score), summary: SM.Gaps.analyse([], {}).summary, intel_loaded: !!this.intel }; // summary recomputed on demand
      SM.Search.rebuild(this);
      SM.emit('store:loaded');
    },
    profile() { return SM.FW.profile(this.activeProfileId); },
    telemetry() { return SM.Coverage.availableTelemetry(this.logSources); },
    alertStats() { const m = {}; const days = Number(this.settings.observation_days || 30); for (const r of this.rules) m[r.rule_id] = { alerts: 0, offenses: 0, false_positives: 0, observation_days: days }; for (const a of this.alerts) { const k = a.rule_id; if (!m[k]) m[k] = { alerts: 0, offenses: 0, false_positives: 0, observation_days: days }; m[k].alerts += (a.count || 1); if (a.false_positive) m[k].false_positives += (a.count || 1); } for (const o of this.offenses) for (const rid of (o.rule_ids || [])) { if (!m[rid]) m[rid] = { alerts: 0, offenses: 0, false_positives: 0, observation_days: days }; m[rid].offenses += 1; } for (const r of this.rules) if (r.trigger_count != null && m[r.rule_id] && !m[r.rule_id].alerts) m[r.rule_id].alerts = r.trigger_count; return m; },
    staleLogSources() { const s = new Set(); for (const l of this.logSources) if (l.health_status === 'stale' || l.health_status === 'inactive' || l.collection_status === 'inactive') s.add(l.source_type); return s; },
    testsByRule() { const m = {}; for (const t of this.tests) (m[t.rule_id] = m[t.rule_id] || []).push(t); return m; },

    async addRules(rules, batchId) { for (const r of rules) { r.import_batch = batchId; r.imported_at = SM.now(); } await SM.DB.bulkPut('rules', rules); const ids = new Set(rules.map(r => r.rule_id)); this.rules = this.rules.filter(r => !ids.has(r.rule_id)).concat(rules); SM.Search.rebuild(this); SM.emit('rules:changed'); },
    async deleteRule(id) { await SM.DB.delete('rules', id); this.rules = this.rules.filter(r => r.rule_id !== id); SM.emit('rules:changed'); },
    async clearRules() { await SM.DB.clear('rules'); await SM.DB.clear('import_batches'); this.rules = []; SM.emit('rules:changed'); },
    async saveCoverage(result) { await SM.DB.clear('coverage'); await SM.DB.bulkPut('coverage', result.results); await SM.DB.setting('coverage_assessed_at', result.assessed_at); this.coverage = result; SM.emit('coverage:changed'); },
    async saveGaps(result) { await SM.DB.clear('gaps'); await SM.DB.bulkPut('gaps', result.gaps); this.gaps = result.gaps; this.gapAnalysis = result; SM.emit('gaps:changed'); },
    async saveGenerated(recs) { await SM.DB.bulkPut('generated_rules', recs); const ids = new Set(recs.map(r => r.id)); this.generated = this.generated.filter(r => !ids.has(r.id)).concat(recs); SM.emit('generated:changed'); },
    async upsertLogSources(list) { await SM.DB.bulkPut('log_sources', list); const ids = new Set(list.map(l => l.id)); this.logSources = this.logSources.filter(l => !ids.has(l.id)).concat(list); SM.emit('logsources:changed'); },
    async upsertAssets(list) { await SM.DB.bulkPut('assets', list); const ids = new Set(list.map(a => a.asset_id)); this.assets = this.assets.filter(a => !ids.has(a.asset_id)).concat(list); SM.emit('assets:changed'); },
    async upsertOffenses(list) { await SM.DB.bulkPut('offenses', list); const ids = new Set(list.map(o => o.id)); this.offenses = this.offenses.filter(o => !ids.has(o.id)).concat(list); SM.emit('offenses:changed'); },
    async upsertAlerts(list) { await SM.DB.bulkPut('alerts', list); const ids = new Set(list.map(a => a.id)); this.alerts = this.alerts.filter(a => !ids.has(a.id)).concat(list); SM.emit('alerts:changed'); },
    async saveTest(test) { await SM.DB.put('validation_tests', test); const i = this.tests.findIndex(t => t.test_id === test.test_id); if (i >= 0) this.tests[i] = test; else this.tests.push(test); SM.emit('tests:changed'); },
    async addLifecycleEvent(ev) { ev.id = ev.id || SM.uid('lc'); ev.at = ev.at || SM.now(); await SM.DB.put('lifecycle_events', ev); this.lifecycleEvents.push(ev); SM.emit('lifecycle:changed'); },
    async addAnnotation(an) { an.id = an.id || SM.uid('an'); an.at = SM.now(); an.author = this.settings.analyst || 'analyst'; await SM.DB.put('annotations', an); this.annotations.push(an); SM.emit('annotations:changed'); return an; },
    async saveReport(rep) { await SM.DB.put('reports', rep); this.reports.unshift(rep); SM.emit('reports:changed'); },
    async saveFilter(f) { f.id = f.id || SM.uid('flt'); await SM.DB.put('saved_filters', f); const i = this.savedFilters.findIndex(x => x.id === f.id); if (i >= 0) this.savedFilters[i] = f; else this.savedFilters.push(f); SM.emit('filters:changed'); return f; },
    async deleteFilter(id) { await SM.DB.delete('saved_filters', id); this.savedFilters = this.savedFilters.filter(f => f.id !== id); SM.emit('filters:changed'); },
    async setSetting(k, v) { this.settings[k] = v; await SM.DB.setting(k, v); SM.emit('settings:changed', k); },
    async setWeights(kind, w) { this.weights[kind] = w; await this.setSetting('weights_' + kind, w); },
    async setIntel(map) { this.intel = map; await this.setSetting('threat_intel', map); SM.emit('intel:changed'); },
    rulesByTechnique(tid) { const p = SM.parentTechnique(tid); return this.rules.filter(r => r.attack_techniques.includes(tid) || (!tid.includes('.') && r.attack_techniques.some(x => x.split('.')[0] === tid)) || r.attack_techniques.includes(p) === false && false); },
    coverageFor(tid) { return this.coverage ? this.coverage.results.find(r => r.technique_id === tid) : null; },
    gapFor(tid) { return this.gaps.find(g => g.technique_id === tid) || null; }
  };
  SM.Store = Store;

  // ---------------- Full analysis pipeline ----------------
  SM.runCoverage = async (opts = {}) => {
    const S = SM.Store; const result = SM.Coverage.assess({ rules: S.rules, techniques: SM.FW.allTechniques(), logSources: S.logSources, tests: S.tests, profile: S.profile(), assets: S.assets, scenarioKB: SM.Scenarios ? SM.Scenarios.forCoverage() : {}, weights: S.weights.coverage, telemetryFor: (id) => SM.FW.telemetryFor(id), alertStats: S.alertStats() });
    if (!opts.noSave) await S.saveCoverage(result); return result;
  };
  SM.runGaps = async (opts = {}) => {
    const S = SM.Store; if (!S.coverage) await SM.runCoverage();
    const result = SM.Gaps.analyse(S.coverage.results, { assets: S.assets, telemetry: S.telemetry(), intel: S.intel, telemetryFor: (id) => SM.FW.telemetryFor(id), weights: S.weights.gap });
    if (!opts.noSave) await S.saveGaps(result); return result;
  };
})(globalThis.SM = globalThis.SM || {});
