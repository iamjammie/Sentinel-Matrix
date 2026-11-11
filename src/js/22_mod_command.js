/* SENTINEL MATRIX — Command Centre dashboard. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;

  SM.registerModule('command', {
    title: 'Command Centre', subtitle: SM.TAGLINE,
    render(body, params, actions) {
      actions.append(
        h('button', { class: 'btn primary', onClick: runAssessment }, '▶ Run full assessment'),
        h('button', { class: 'btn ghost', onClick: () => SM.App.go('reports') }, 'Generate report')
      );
      const S = SM.Store;
      body.append(ui.demoBanner() || document.createComment(''));
      if (!S.rules.length) { body.append(ui.empty('Welcome to Sentinel Matrix', 'No rules are loaded. Import your SIEM detection rules, or load demo data to explore the platform.', h('div', { class: 'row' }, h('button', { class: 'btn primary', onClick: () => SM.App.go('inventory', { tab: 'import' }) }, 'Import rules'), h('button', { class: 'btn', onClick: async () => { await SM.Demo.load(); SM.App.go('command'); } }, 'Load demo data')))); return; }
      body.append(h('div', { id: 'cc-filters' }));
      body.append(h('div', { id: 'cc-body' }));
      renderFilters(); renderBody();
    }
  });

  const flt = {};
  function renderFilters() {
    const box = SM.clear(SM.$('#cc-filters')); const bar = h('div', { class: 'filterbar' });
    const mk = (label, key, opts) => h('div', { class: 'field' }, h('label', label), h('select', { onChange: e => { flt[key] = e.target.value; renderBody(); } }, h('option', { value: '' }, 'All'), opts.map(o => h('option', { value: o, selected: flt[key] === o }, o))));
    bar.append(
      mk('SIEM platform', 'platform', SM.uniq(SM.Store.rules.map(r => r.source_platform))),
      mk('Severity', 'severity', SM.SEVERITIES),
      mk('Detection status', 'enabled', ['enabled', 'disabled', 'unknown']),
      mk('Rule source', 'mapping', ['explicit', 'inferred']),
      mk('Network zone', 'zone', SM.uniq(SM.Store.logSources.map(l => l.zone)).filter(Boolean)),
      mk('Validation', 'validation', ['validated', 'not_validated']),
      h('button', { class: 'btn sm ghost', onClick: () => { for (const k in flt) delete flt[k]; renderFilters(); renderBody(); } }, 'Reset')
    );
    box.append(bar);
  }
  function filteredRules() { let r = SM.Store.rules; if (flt.platform) r = r.filter(x => x.source_platform === flt.platform); if (flt.severity) r = r.filter(x => x.severity === flt.severity); if (flt.enabled) r = r.filter(x => x.enabled_status === flt.enabled); if (flt.mapping === 'explicit') r = r.filter(x => x.mapping_source.startsWith('explicit') || x.mapping_source === 'text-reference'); else if (flt.mapping === 'inferred') r = r.filter(x => x.mapping_source === 'inferred'); if (flt.validation) r = r.filter(x => x.validation_status === flt.validation); return r; }

  function renderBody() {
    const S = SM.Store; const box = SM.clear(SM.$('#cc-body'));
    const rules = filteredRules();
    const enabled = rules.filter(r => r.enabled_status === 'enabled'); const disabled = rules.filter(r => r.enabled_status === 'disabled');
    const fpByFp = SM.groupBy(rules, r => r.fingerprint); const dupes = SM.sum(Array.from(fpByFp.values()), g => Math.max(0, g.length - 1));
    const unmapped = rules.filter(r => !r.attack_techniques.length);
    const cov = S.coverage; const tel = S.telemetry();
    const covCounts = cov ? cov.summary.counts : {};
    const techAssessed = cov ? cov.summary.applicable : 0;
    const covered = (covCounts.VALIDATED || 0) + (covCounts.FULLY_COVERED || 0);
    const partial = covCounts.PARTIALLY_COVERED || 0; const uncovered = covCounts.NOT_COVERED || 0;
    const weak = (covCounts.WEAK_COVERAGE || 0) + (covCounts.UNVALIDATED_COVERAGE || 0);
    const critGaps = S.gaps.filter(g => g.risk_level === 'critical').length;
    const needTuning = rules.filter(r => { const st = S.alertStats()[r.rule_id]; return st && st.observation_days && st.alerts / st.observation_days > 500; }).length;
    const noValidation = rules.filter(r => r.enabled_status === 'enabled' && r.validation_status !== 'validated').length;
    const missingTel = cov ? cov.results.filter(r => r.classification !== 'NOT_APPLICABLE' && (r.missing_log_source_types || []).length).length : 0;
    const openOffenses = S.offenses.filter(o => o.status === 'open' || o.status === 'OPEN').length;
    const alertVol = SM.sum(S.alerts, a => a.count || 1);
    const lsHealthy = S.logSources.filter(l => l.health_status === 'healthy').length;

    // KPI grid
    const go = (route, p) => () => SM.App.go(route, p);
    box.append(h('div', { class: 'grid kpi' },
      ui.kpi('Total rules imported', SM.fmtNum(rules.length), { color: 'cyan', onClick: go('inventory') }),
      ui.kpi('Active rules', SM.fmtNum(enabled.length), { color: 'green', onClick: go('inventory', { tab: 0, focus: 'enabled' }) }),
      ui.kpi('Disabled rules', SM.fmtNum(disabled.length), { onClick: go('inventory') }),
      ui.kpi('Duplicate rules', SM.fmtNum(dupes), { color: dupes ? 'amber' : undefined, onClick: go('inventory') }),
      ui.kpi('Rules w/o ATT&CK', SM.fmtNum(unmapped.length), { color: unmapped.length ? 'amber' : undefined, onClick: go('inventory') }),
      ui.kpi('Techniques assessed', SM.fmtNum(techAssessed), { onClick: go('matrix') }),
      ui.kpi('Covered techniques', SM.fmtNum(covered), { color: 'green', onClick: go('coverage') }),
      ui.kpi('Partially covered', SM.fmtNum(partial), { color: 'amber', onClick: go('coverage') }),
      ui.kpi('Uncovered techniques', SM.fmtNum(uncovered), { color: uncovered ? 'red' : undefined, onClick: go('coverage') }),
      ui.kpi('Critical detection gaps', SM.fmtNum(critGaps), { color: critGaps ? 'red' : undefined, onClick: go('gaps') }),
      ui.kpi('Weak detections', SM.fmtNum(weak), { color: weak ? 'orange' : undefined, onClick: go('coverage') }),
      ui.kpi('Rules requiring tuning', SM.fmtNum(needTuning), { color: needTuning ? 'amber' : undefined, onClick: go('offenses') }),
      ui.kpi('Lacking validation', SM.fmtNum(noValidation), { onClick: go('validation') }),
      ui.kpi('Missing telemetry deps', SM.fmtNum(missingTel), { color: missingTel ? 'amber' : undefined, onClick: go('logsources') }),
      ui.kpi('Live offenses', SM.fmtNum(openOffenses), { color: openOffenses ? 'orange' : undefined, onClick: go('offenses') }),
      ui.kpi('Alert volume', SM.fmtNum(alertVol), { onClick: go('offenses') }),
      ui.kpi('Log source health', S.logSources.length ? lsHealthy + '/' + S.logSources.length : '—', { color: 'cyan', onClick: go('logsources') })
    ));

    if (!cov) { box.append(h('div', { class: 'card', style: { marginTop: '14px' } }, h('div', { class: 'row spread' }, h('div', null, h('strong', 'No coverage assessment yet.'), h('div', { class: 'small muted' }, 'Run the assessment to populate coverage, gaps and the ATT&CK matrix.')), h('button', { class: 'btn primary', onClick: runAssessment }, '▶ Run full assessment')))); return; }

    // composite scores
    const dims = cov.summary.dimensions;
    box.append(h('div', { class: 'grid c2', style: { marginTop: '14px' } },
      ui.card('Detection coverage scores', h('div', null,
        h('div', { class: 'row', style: { gap: '18px', flexWrap: 'wrap', justifyContent: 'center' } },
          scoreBlock('Composite', cov.summary.composite, 'Configurable analytical indicator'),
          scoreBlock('Mapping', dims.mapping), scoreBlock('Configured', dims.configured), scoreBlock('Operational', dims.operational), scoreBlock('Validated', dims.validated), scoreBlock('Telemetry', dims.telemetry), scoreBlock('Asset', dims.asset)
        ),
        h('div', { class: 'xs muted', style: { marginTop: '10px', textAlign: 'center' } }, 'Composite is a weighted indicator across six dimensions — click any dimension in Detection Coverage for its evidence. Coverage is not a simple rule count.')
      ), 'weighted'),
      ui.card('Coverage classification', h('div', null,
        SM.chartDonut(Object.entries(covCounts).filter(([k]) => k !== 'NOT_APPLICABLE').map(([k, v]) => ({ label: SM.COVERAGE[k].label, value: v, color: SM.COV_COLORS[k], key: k })), { centerLabel: { big: SM.pct(covered, techAssessed) + '%', small: 'covered' }, onClick: (d) => SM.App.go('coverage', { filter: d.key }) }),
        SM.legend(Object.entries(covCounts).filter(([k]) => k !== 'NOT_APPLICABLE').map(([k, v]) => ({ label: SM.COVERAGE[k].label, color: SM.COV_COLORS[k], value: v })))
      ))
    ));

    // tactic coverage + severity + log source
    const byTactic = SM.FW.tacticsOrdered().map(t => { const b = cov.summary.by_tactic[t.id] || { applicable: 0, covered: 0, partial: 0, weak: 0, none: 0 }; return { id: t.id, label: t.name, segments: [{ label: 'Covered', value: b.covered, color: SM.CHART_COLORS.cyan }, { label: 'Partial', value: b.partial, color: '#e5d04a' }, { label: 'Weak', value: b.weak, color: SM.CHART_COLORS.orange }, { label: 'None', value: b.none, color: SM.CHART_COLORS.red }], value: b.applicable }; });
    box.append(h('div', { class: 'grid c2', style: { marginTop: '14px' } },
      ui.card('ATT&CK tactic coverage', SM.chartVBar(byTactic, { stacked: true, height: 240 }), 'by technique count'),
      ui.card('Rule severity distribution', SM.chartHBar(SM.SEVERITIES.map(s => ({ label: s, value: rules.filter(r => r.severity === s).length, color: ({ critical: SM.CHART_COLORS.red, high: SM.CHART_COLORS.orange, medium: SM.CHART_COLORS.amber, low: SM.CHART_COLORS.cyan, informational: SM.CHART_COLORS.grey }[s]) })), { unit: 'rules' }))
    ));
    box.append(h('div', { class: 'grid c2', style: { marginTop: '14px' } },
      ui.card('Coverage by log source type', SM.chartHBar(coverageByLogSource(cov).slice(0, 10), { unit: 'techniques', color: SM.CHART_COLORS.blue }), 'techniques whose telemetry depends on each source'),
      ui.card('Detection quality distribution', qualityDist(rules))
    ));
    box.append(h('div', { class: 'grid c2', style: { marginTop: '14px' } },
      ui.card('Rule duplication analysis', dupAnalysis(rules, fpByFp)),
      ui.card('Detection gap prioritisation', SM.chartHBar(S.gaps.slice(0, 10).map(g => ({ label: g.technique_id + ' ' + SM.truncate(g.technique_name, 14), value: g.priority_score, color: g.risk_level === 'critical' ? SM.CHART_COLORS.red : g.risk_level === 'high' ? SM.CHART_COLORS.orange : SM.CHART_COLORS.amber })), { max: 100, unit: 'priority', onClick: (d) => SM.App.go('gaps') }))
    ));
    box.append(h('div', { class: 'grid c2', style: { marginTop: '14px' } },
      ui.card('Coverage by enterprise zone', zoneCoverage()),
      ui.card('Detection validation status', validationStatus(rules))
    ));
  }
  function scoreBlock(label, score, sub) { return h('div', { style: { textAlign: 'center' } }, SM.scoreRing(score, { size: label === 'Composite' ? 96 : 76, label }), sub ? h('div', { class: 'xs muted', style: { maxWidth: '110px' } }, sub) : null); }
  function coverageByLogSource(cov) { const m = {}; for (const r of cov.results) { if (r.classification === 'NOT_APPLICABLE') continue; for (const t of r.required_log_source_types || []) { m[t] = m[t] || { total: 0, ok: 0 }; m[t].total++; if (['VALIDATED', 'FULLY_COVERED'].includes(r.classification)) m[t].ok++; } } return Object.entries(m).map(([t, v]) => ({ label: SM.FW.logSourceType(t).name, value: v.total })).sort((a, b) => b.value - a.value); }
  function qualityDist(rules) { const tel = SM.Store.telemetry(); const buckets = { 'A (80+)': 0, 'B (65-79)': 0, 'C (50-64)': 0, 'D (35-49)': 0, 'E (<35)': 0 }; const ctx = { telemetry: tel, alertStats: SM.Store.alertStats(), testsByRule: SM.Store.testsByRule(), weights: SM.Store.weights.quality }; for (const r of rules) { const g = SM.Quality.assess(r, ctx).grade; buckets[{ A: 'A (80+)', B: 'B (65-79)', C: 'C (50-64)', D: 'D (35-49)', E: 'E (<35)' }[g]]++; } return SM.chartHBar(Object.entries(buckets).map(([k, v], i) => ({ label: k, value: v, color: [SM.CHART_COLORS.green, SM.CHART_COLORS.cyan, SM.CHART_COLORS.amber, SM.CHART_COLORS.orange, SM.CHART_COLORS.red][i] })), { unit: 'rules' }); }
  function dupAnalysis(rules, fpByFp) { const groups = Array.from(fpByFp.entries()).filter(([, g]) => g.length > 1).sort((a, b) => b[1].length - a[1].length); if (!groups.length) return h('div', { class: 'small muted' }, 'No duplicate detection logic found across ' + rules.length + ' rules.'); return h('div', null, h('div', { class: 'small muted', style: { marginBottom: '8px' } }, groups.length + ' groups of rules share identical detection logic:'), h('table', { class: 'plain' }, h('tbody', groups.slice(0, 6).map(([fp, g]) => h('tr', h('td', h('span', { class: 'mono xs' }, fp)), h('td', g.length + ' rules'), h('td', h('span', { class: 'xs muted' }, SM.truncate(g.map(r => r.rule_name).join(', '), 50)))))))); }
  function zoneCoverage() { const S = SM.Store; if (!S.logSources.length && !S.assets.length) return h('div', { class: 'small muted' }, 'Load log sources and assets to assess per-zone coverage.'); const zones = SM.uniq([...S.logSources.map(l => l.zone), ...S.assets.map(a => a.zone)].filter(Boolean)); const data = zones.map(z => { const sources = S.logSources.filter(l => l.zone === z); const healthy = sources.filter(l => l.health_status === 'healthy').length; return { label: z, value: sources.length ? Math.round(100 * healthy / sources.length) : 0 }; }); return SM.chartHBar(data, { max: 100, unit: '% sources healthy', color: SM.CHART_COLORS.violet }); }
  function validationStatus(rules) { const tested = new Set(SM.Store.tests.map(t => t.rule_id)); const passed = new Set(SM.Store.tests.filter(t => t.status === 'PASS').map(t => t.rule_id)); const failed = new Set(SM.Store.tests.filter(t => t.status === 'FAIL').map(t => t.rule_id)); return SM.chartDonut([{ label: 'Validated (PASS)', value: passed.size, color: SM.CHART_COLORS.green }, { label: 'Failed', value: failed.size, color: SM.CHART_COLORS.red }, { label: 'Tested, other', value: tested.size - passed.size - failed.size, color: SM.CHART_COLORS.amber }, { label: 'Never tested', value: rules.length - tested.size, color: SM.CHART_COLORS.grey }], { centerLabel: { big: SM.fmtNum(passed.size), small: 'validated' } }); }

  async function runAssessment() {
    if (!SM.Store.rules.length) return SM.toast('Import rules first', 'warn');
    const prog = h('div', { class: 'progress' }, h('div', { style: { width: '10%' } }));
    const m = SM.modal({ title: 'Running full assessment', body: h('div', null, h('div', { id: 'assess-step', class: 'small muted', style: { marginBottom: '8px' } }, 'Starting…'), prog) });
    const step = (t, p) => { SM.$('#assess-step').textContent = t; prog.firstChild.style.width = p + '%'; return new Promise(r => setTimeout(r, 30)); };
    await step('Analysing ATT&CK coverage across ' + SM.FW.allTechniques().length + ' techniques…', 35);
    const cov = await SM.runCoverage();
    await step('Identifying detection gaps and prioritising…', 70);
    await SM.runGaps();
    await step('Updating search index…', 90);
    SM.Search.rebuild(SM.Store);
    await step('Done', 100);
    m.close();
    SM.toast('Assessment complete — composite ' + cov.summary.composite + ', ' + SM.Store.gaps.filter(g => g.risk_level === 'critical').length + ' critical gaps.', 'ok');
    SM.App.go('command');
  }
  SM.runAssessment = runAssessment;
})(globalThis.SM = globalThis.SM || {});
