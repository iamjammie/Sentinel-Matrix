/* SENTINEL MATRIX — Gap Analysis module. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;

  SM.registerModule('gaps', {
    title: 'Gap Analysis', subtitle: 'Prioritised detection gaps with telemetry, exposure and recommended action',
    render(body, params, actions) {
      actions.append(h('button', { class: 'btn primary', onClick: () => SM.runGaps().then(() => SM.App.go('gaps')) }, '↻ Reanalyse'), h('button', { class: 'btn ghost', onClick: exportGaps }, '⬇ Export'), h('button', { class: 'btn ghost', onClick: () => SM.App.go('settings', { tab: 'scoring' }) }, 'Priority weights'));
      const S = SM.Store;
      if (!S.gaps.length) { body.append(ui.empty('No gaps analysed', S.coverage ? 'No open gaps, or analysis not run.' : 'Run a coverage assessment and gap analysis first.', h('button', { class: 'btn primary', onClick: () => SM.runGaps().then(() => SM.App.go('gaps')) }, 'Run gap analysis'))); return; }
      const summ = SM.Gaps.analyse(S.coverage.results, { assets: S.assets, telemetry: S.telemetry(), intel: S.intel, telemetryFor: id => SM.FW.telemetryFor(id), weights: S.weights.gap }).summary;
      if (!S.intel) body.append(h('div', { class: 'demo-banner', style: { background: 'rgba(25,211,243,.08)', borderColor: 'rgba(25,211,243,.4)', color: '#bdeefb' } }, 'ⓘ', h('span', null, 'No threat-intelligence dataset imported. The "threat relevance" dimension uses a neutral placeholder and is marked UNKNOWN per gap. Import intel in Settings → Threat Intelligence to weight gaps by prevalence.')));
      body.append(h('div', { class: 'grid kpi' },
        ui.kpi('Total gaps', SM.fmtNum(summ.total), { color: 'cyan' }),
        ui.kpi('Critical', SM.fmtNum(summ.critical), { color: 'red' }),
        ui.kpi('High', SM.fmtNum(summ.high), { color: 'orange' }),
        ui.kpi('Medium', SM.fmtNum(summ.medium), { color: 'amber' }),
        ui.kpi('Low', SM.fmtNum(summ.low)),
        ui.kpi('With rule proposals', SM.fmtNum(summ.with_proposals), { color: 'green' })
      ));
      body.append(h('div', { class: 'grid c2', style: { margin: '14px 0' } },
        ui.card('Top priority gaps', SM.chartHBar(S.gaps.slice(0, 12).map(g => ({ label: g.technique_id + ' ' + SM.truncate(g.technique_name, 12), value: g.priority_score, color: g.risk_level === 'critical' ? SM.CHART_COLORS.red : g.risk_level === 'high' ? SM.CHART_COLORS.orange : SM.CHART_COLORS.amber })), { max: 100, unit: 'priority' })),
        ui.card('Gaps by tactic', SM.chartHBar(gapsByTactic(S.gaps), { unit: 'gaps', color: SM.CHART_COLORS.violet }))
      ));
      const filterbar = h('div', { class: 'filterbar' }); const st = { risk: '', cov: '', q: '', tactic: '' };
      const mk = (label, key, opts) => h('div', { class: 'field' }, h('label', label), h('select', { onChange: e => { st[key] = e.target.value; apply(); } }, h('option', { value: '' }, 'All'), opts.map(o => h('option', { value: o.v }, o.l))));
      filterbar.append(h('div', { class: 'field', style: { flex: 2 } }, h('label', 'Search'), h('input', { type: 'text', value: params.focus || '', placeholder: 'technique', onInput: e => { st.q = e.target.value; apply(); } })), mk('Risk', 'risk', ['critical', 'high', 'medium', 'low'].map(v => ({ v, l: v }))), mk('Current coverage', 'cov', ['NOT_COVERED', 'WEAK_COVERAGE', 'UNVALIDATED_COVERAGE', 'PARTIALLY_COVERED'].map(v => ({ v, l: SM.COVERAGE[v].label }))), mk('Tactic', 'tactic', SM.FW.tacticsOrdered().map(t => ({ v: t.id, l: t.name }))));
      body.append(filterbar);
      const table = SM.VTable([
        { key: 'priority_score', label: '#', width: '0.4fr', align: 'right', render: g => h('strong', g.priority_score) },
        { key: 'technique_id', label: 'Technique', width: '2fr', render: g => h('div', null, h('span', { class: 'mono' }, g.technique_id), ' ', SM.truncate(g.technique_name, 32)) },
        { key: 'risk_level', label: 'Risk', width: '0.8fr', sort: (a, b) => b.priority_score - a.priority_score, render: g => ui.riskTag(g.risk_level) },
        { key: 'current_coverage', label: 'Coverage', width: '1.1fr', render: g => ui.covTag(g.current_coverage) },
        { key: 'missing_telemetry', label: 'Missing telemetry', width: '1.4fr', render: g => g.missing_telemetry.length ? h('span', { class: 'xs' }, g.missing_telemetry.map(x => SM.FW.logSourceType(x).name).join(', ')) : h('span', { class: 'xs muted' }, 'telemetry OK') },
        { key: 'proposed_rule_available', label: 'Proposal', width: '0.7fr', render: g => g.proposed_rule_available ? h('span', { class: 'tag green' }, SM.Scenarios.get(g.technique_id).scenarios.length) : h('span', { class: 'tag grey' }, '—') }
      ], { idKey: 'gap_id', maxHeight: 520, sortKey: 'priority_score', onRow: openGap });
      body.append(table.el);
      function apply() { let rows = S.gaps; if (st.risk) rows = rows.filter(g => g.risk_level === st.risk); if (st.cov) rows = rows.filter(g => g.current_coverage === st.cov); if (st.tactic) rows = rows.filter(g => (g.tactics || []).includes(st.tactic)); if (st.q) { const q = st.q.toLowerCase(); rows = rows.filter(g => g.technique_id.toLowerCase().includes(q) || g.technique_name.toLowerCase().includes(q)); } table.setRows(rows, S.gaps.length); }
      apply();
      if (params.focus) setTimeout(() => { const g = S.gaps.find(x => x.technique_id === params.focus); if (g) openGap(g); }, 100);
    }
  });
  function gapsByTactic(gaps) { const m = {}; for (const g of gaps) for (const t of g.tactics || []) m[t] = (m[t] || 0) + 1; return Object.entries(m).map(([t, v]) => ({ label: SM.FW.tacticName(t), value: v })).sort((a, b) => b.value - a.value); }

  function openGap(g) {
    const t = SM.FW.technique(g.technique_id);
    const body = h('div');
    body.append(h('div', { class: 'row', style: { marginBottom: '8px' } }, ui.riskTag(g.risk_level), h('span', { class: 'tag' }, 'Priority ' + g.priority_score), ui.covTag(g.current_coverage), h('span', { class: 'tag ' + (g.confidence === 'high' ? 'green' : 'amber') }, g.confidence)));
    body.append(h('dl', { class: 'kv' },
      h('dt', 'Gap ID'), h('dd', h('span', { class: 'mono' }, g.gap_id)),
      h('dt', 'Technique'), h('dd', ui.techLink(g.technique_id, g.technique_id + ' — ' + g.technique_name)),
      h('dt', 'Tactics'), h('dd', (g.tactics || []).map(x => SM.FW.tacticName(x)).join(', ')),
      h('dt', 'Business impact'), h('dd', g.business_impact),
      h('dt', 'Existing rules'), h('dd', g.existing_rule_ids.length ? g.existing_rule_ids.length + ' mapped' : 'None'),
      h('dt', 'Required telemetry'), h('dd', (g.required_telemetry || []).map(x => SM.FW.logSourceType(x).name).join(', ') || '—'),
      h('dt', 'Available telemetry'), h('dd', (g.available_telemetry || []).map(x => SM.FW.logSourceType(x).name).join(', ') || '—'),
      h('dt', 'Missing telemetry'), h('dd', (g.missing_telemetry || []).length ? h('span', { style: { color: 'var(--red)' } }, g.missing_telemetry.map(x => SM.FW.logSourceType(x).name).join(', ')) : 'None'),
      h('dt', 'Asset exposure'), h('dd', g.asset_exposure.critical_assets_applicable + ' applicable critical assets' + (g.asset_exposure.zones_without_telemetry.length ? '; zones without telemetry: ' + g.asset_exposure.zones_without_telemetry.join(', ') : '')),
      h('dt', 'Missing scenarios'), h('dd', g.missing_scenarios.length ? g.missing_scenarios.join(', ') + ' (of ' + g.known_scenario_count + ')' : (g.known_scenario_count ? 'none — all known scenarios addressed' : 'no templates bundled')),
      h('dt', 'Validation'), h('dd', g.validation_requirements)
    ));
    // priority dimensions
    body.append(h('h3', { style: { marginTop: '12px' } }, 'Priority breakdown'));
    body.append(SM.chartHBar(Object.entries(g.priority_dimensions).map(([k, v]) => ({ label: k.replace(/_/g, ' '), value: v, color: k === 'threat_relevance' && !g.threat_relevance_known ? SM.CHART_COLORS.grey : undefined })), { max: 100 }));
    if (!g.threat_relevance_known) body.append(h('div', { class: 'xs muted' }, '⚠ ' + g.threat_relevance_note));
    body.append(ui.card('Recommended action', h('ul', { class: 'small', style: { margin: 0, paddingLeft: '18px' } }, g.recommended_action.map(a => h('li', a)))));
    const foot = h('div', { class: 'row', style: { marginTop: '12px' } });
    if (g.proposed_rule_available) foot.append(h('button', { class: 'btn primary', onClick: () => { SM.drawer.close(); SM.App.go('generator', { technique: g.technique_id }); } }, 'Generate proposed rules'));
    foot.append(h('button', { class: 'btn', onClick: () => SM.App.go('matrix', { focus: g.technique_id }) }, 'View technique'));
    foot.append(h('button', { class: 'btn ghost', onClick: async () => { const note = await SM.prompt('Analyst review item', 'Add a note / assign owner'); if (note !== null) { await SM.Store.addAnnotation({ target_id: g.gap_id, type: 'gap_review', text: note }); SM.toast('Review item saved', 'ok'); } } }, 'Create review item'));
    body.append(foot);
    const anns = SM.Store.annotations.filter(a => a.target_id === g.gap_id);
    if (anns.length) body.append(ui.card('Review notes', h('div', null, anns.map(a => h('div', { class: 'small', style: { marginBottom: '4px' } }, h('span', { class: 'xs muted mono' }, SM.fmtDate(a.at) + ' ' + a.author + ': '), a.text)))));
    SM.drawer.open('Gap ' + g.technique_id, body, g.technique_name);
  }
  function exportGaps() {
    const g = SM.Store.gaps; if (!g.length) return SM.toast('No gaps', 'warn');
    const doExport = (f) => { if (f === 'JSON') SM.download('gap-analysis.json', JSON.stringify(g, null, 1), 'application/json'); else SM.download('gap-analysis.csv', SM.toCSV(g.map(x => ({ gap_id: x.gap_id, technique: x.technique_id, name: x.technique_name, risk: x.risk_level, priority: x.priority_score, coverage: x.current_coverage, missing_telemetry: x.missing_telemetry.join('|'), threat_relevance_known: x.threat_relevance_known, action: x.recommended_action.join('; ') }))), 'text/csv'); SM.$('#modal-back').classList.remove('open'); };
    const btns = ['CSV', 'JSON'].map(f => h('button', { class: 'btn', onClick: () => doExport(f) }, f));
    SM.modal({ title: 'Export gaps', body: h('div', { class: 'row' }, btns) });
  }
})(globalThis.SM = globalThis.SM || {});
