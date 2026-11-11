/* SENTINEL MATRIX — Detection Coverage + ATT&CK Matrix modules. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;

  SM.registerModule('coverage', {
    title: 'Detection Coverage', subtitle: 'Weighted, evidence-based ATT&CK coverage — not a rule count',
    render(body, params, actions) {
      actions.append(h('button', { class: 'btn primary', onClick: () => SM.runCoverage().then(() => SM.App.go('coverage')) }, '↻ Reassess'), h('button', { class: 'btn ghost', onClick: () => SM.App.go('matrix') }, 'Open matrix'), exportBtn());
      const cov = SM.Store.coverage;
      if (!cov) { body.append(ui.empty('No coverage assessment', 'Run a coverage assessment to evaluate your detection posture.', h('button', { class: 'btn primary', onClick: () => SM.runCoverage().then(() => SM.App.go('coverage')) }, 'Run assessment'))); return; }
      body.append(h('div', { class: 'small muted', style: { marginBottom: '12px' } }, 'Assessed ' + SM.fmtDate(cov.assessed_at) + ' · ' + cov.summary.applicable + ' applicable techniques' + (cov.telemetry_known ? '' : ' · ⚠ log source inventory not loaded — telemetry dimension is low-confidence')));
      // dimension cards (clickable → methodology)
      const dims = cov.summary.dimensions;
      const dimCards = h('div', { class: 'grid c3' }, [['mapping', 'Mapping Coverage'], ['configured', 'Configured Coverage'], ['operational', 'Operational Coverage'], ['validated', 'Validated Coverage'], ['telemetry', 'Telemetry Coverage'], ['asset', 'Enterprise Asset Coverage']].map(([k, label]) => h('div', { class: 'kpi-card c-' + (dims[k] >= 70 ? 'green' : dims[k] >= 45 ? 'amber' : 'red'), onClick: () => explainDim(k) }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, dims[k]), h('div', { class: 'delta' }, 'click for methodology'))));
      body.append(ui.card('Coverage dimensions (composite ' + cov.summary.composite + ')', dimCards, 'weighted indicator'));
      // coverage table
      const filterbar = h('div', { class: 'filterbar' });
      const state = { tactic: '', cls: params.filter || '', platform: '', q: '' };
      const mk = (label, key, opts) => h('div', { class: 'field' }, h('label', label), h('select', { onChange: e => { state[key] = e.target.value; apply(); } }, h('option', { value: '' }, 'All'), opts.map(o => h('option', { value: o.v, selected: state[key] === o.v }, o.l))));
      filterbar.append(
        h('div', { class: 'field', style: { flex: 2 } }, h('label', 'Search technique'), h('input', { type: 'text', placeholder: 'T1558 or name…', onInput: e => { state.q = e.target.value; apply(); } })),
        mk('Tactic', 'tactic', SM.FW.tacticsOrdered().map(t => ({ v: t.id, l: t.name }))),
        mk('Coverage', 'cls', Object.keys(SM.COVERAGE).map(k => ({ v: k, l: SM.COVERAGE[k].label }))),
        mk('Platform', 'platform', SM.FW.attack.platforms.map(p => ({ v: p, l: p })))
      );
      body.append(filterbar);
      const table = SM.VTable([
        { key: 'technique_id', label: 'ID', width: '0.8fr', render: r => h('span', { class: 'mono' + (r.is_subtechnique ? ' muted' : '') }, r.technique_id) },
        { key: 'technique_name', label: 'Technique', width: '2fr', render: r => h('span', { style: r.is_subtechnique ? { paddingLeft: '10px', opacity: .9 } : {} }, r.technique_name) },
        { key: 'tactics', label: 'Tactic', width: '1.2fr', render: r => h('span', { class: 'xs muted' }, (r.tactics || []).map(t => SM.FW.tacticShort(t)).join(', ')) },
        { key: 'classification', label: 'Coverage', width: '1.2fr', sort: (a, b) => SM.COVERAGE[b.classification].rank - SM.COVERAGE[a.classification].rank, render: r => ui.covTag(r.classification) },
        { key: 'composite', label: 'Score', width: '0.6fr', align: 'right', render: r => h('span', { class: r.composite >= 60 ? 'sev-low' : r.composite >= 35 ? 'sev-medium' : 'sev-critical' }, r.composite) },
        { key: 'rule_ids', label: 'Rules', width: '0.5fr', align: 'right', sort: (a, b) => a.rule_ids.length - b.rule_ids.length, render: r => SM.fmtNum(r.rule_ids.length) },
        { key: 'confidence', label: 'Conf.', width: '0.6fr', render: r => h('span', { class: 'tag ' + (r.confidence === 'high' ? 'green' : r.confidence === 'medium' ? 'amber' : 'grey') }, r.confidence) }
      ], { idKey: 'technique_id', maxHeight: 520, sortKey: 'composite', onRow: r => SM.matrixPanel(r.technique_id) });
      body.append(table.el);
      function apply() { let rows = cov.results.filter(r => r.classification !== 'NOT_APPLICABLE' || state.cls === 'NOT_APPLICABLE'); if (state.tactic) rows = rows.filter(r => (r.tactics || []).includes(state.tactic)); if (state.cls) rows = rows.filter(r => r.classification === state.cls); if (state.platform) rows = rows.filter(r => { const t = SM.FW.technique(r.technique_id); return t && (t.platforms || []).includes(state.platform); }); if (state.q) { const q = state.q.toLowerCase(); rows = rows.filter(r => r.technique_id.toLowerCase().includes(q) || r.technique_name.toLowerCase().includes(q)); } table.setRows(rows, cov.results.length); }
      apply();
    }
  });
  function explainDim(k) { const cov = SM.Store.coverage; SM.drawer.open(SM.Coverage.explainScore(k).split('—')[0], h('div', null, h('p', { class: 'small' }, SM.Coverage.explainScore(k)), h('div', { class: 'row', style: { justifyContent: 'center', margin: '14px 0' } }, SM.scoreRing(cov.summary.dimensions[k], { size: 110 })), h('p', { class: 'small muted' }, 'This dimension is averaged across all applicable techniques. The composite score weights it per your configured weights (Settings → Scoring).'), h('h3', 'Lowest-scoring techniques on this dimension'), h('table', { class: 'plain' }, h('tbody', cov.results.filter(r => r.classification !== 'NOT_APPLICABLE').sort((a, b) => a.dimensions[k] - b.dimensions[k]).slice(0, 12).map(r => h('tr', h('td', ui.techLink(r.technique_id)), h('td', SM.truncate(r.technique_name, 28)), h('td', h('span', { class: 'sev-' + (r.dimensions[k] >= 60 ? 'low' : 'critical') }, r.dimensions[k])))))))); }
  function exportBtn() {
    const doExport = (f) => { const cov = SM.Store.coverage; if (!cov) return; if (f === 'JSON') SM.download('coverage.json', JSON.stringify(cov, null, 1), 'application/json'); else SM.download('coverage.csv', SM.toCSV(cov.results.map(r => ({ technique: r.technique_id, name: r.technique_name, tactics: (r.tactics || []).join('|'), coverage: r.classification, composite: r.composite, rules: r.rule_ids.length, confidence: r.confidence, missing_telemetry: (r.missing_log_source_types || []).join('|') }))), 'text/csv'); SM.$('#modal-back').classList.remove('open'); };
    return h('button', { class: 'btn ghost', onClick: () => { if (!SM.Store.coverage) return SM.toast('Run assessment first', 'warn'); const btns = ['CSV', 'JSON'].map(f => h('button', { class: 'btn', onClick: () => doExport(f) }, f)); SM.modal({ title: 'Export coverage', body: h('div', { class: 'row' }, btns) }); } }, '⬇ Export');
  }

  // ---------------- ATT&CK Matrix ----------------
  SM.registerModule('matrix', {
    title: 'ATT&CK Matrix', subtitle: 'Interactive technique coverage — Navigator-style',
    render(body, params, actions) {
      const cov = SM.Store.coverage; const covMap = new Map((cov ? cov.results : []).map(r => [r.technique_id, r]));
      actions.append(
        h('button', { class: 'btn ghost', onClick: () => SM.runCoverage().then(() => SM.App.go('matrix')) }, '↻ Reassess'),
        h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'show-sub', onChange: () => renderMatrix() }), 'Show sub-techniques'),
        h('button', { class: 'btn ghost', onClick: exportMatrix }, '⬇ Export')
      );
      body.append(SM.legend(Object.entries(SM.COVERAGE).map(([k, v]) => ({ label: v.label, color: SM.COV_COLORS[k] }))));
      const filt = h('div', { class: 'filterbar', style: { marginTop: '10px' } });
      const st = { platform: '', cls: '', q: params.focus || '' };
      const mk = (label, key, opts) => h('div', { class: 'field' }, h('label', label), h('select', { onChange: e => { st[key] = e.target.value; renderMatrix(); } }, h('option', { value: '' }, 'All'), opts.map(o => h('option', { value: o.v }, o.l))));
      filt.append(h('div', { class: 'field', style: { flex: 2 } }, h('label', 'Search'), h('input', { type: 'text', value: params.focus || '', placeholder: 'technique id or name', onInput: e => { st.q = e.target.value; renderMatrix(); } })), mk('Platform', 'platform', SM.FW.attack.platforms.map(p => ({ v: p, l: p }))), mk('Coverage', 'cls', Object.keys(SM.COVERAGE).map(k => ({ v: k, l: SM.COVERAGE[k].label }))));
      body.append(filt);
      const wrap = h('div', { class: 'matrix-wrap', id: 'matrix-wrap' }); body.append(wrap);
      function renderMatrix() {
        const showSub = SM.$('#show-sub') && SM.$('#show-sub').checked;
        const m = SM.clear(wrap); const grid = h('div', { class: 'matrix' });
        for (const tac of SM.FW.tacticsOrdered()) {
          let techs = SM.FW.techniquesForTactic(tac.id, { parentsOnly: true });
          if (st.platform) techs = techs.filter(t => (t.platforms || []).includes(st.platform));
          const col = h('div', { class: 'tactic-col' }); col.append(h('div', { class: 'tactic-head' }, tac.name, h('span', { class: 'cnt' }, techs.length)));
          for (const t of techs) {
            if (st.q && !(t.id.toLowerCase().includes(st.q.toLowerCase()) || t.name.toLowerCase().includes(st.q.toLowerCase()))) { if (!showSub) continue; }
            const c = covMap.get(t.id); const cls = c ? c.classification : 'UNKNOWN';
            if (st.cls && cls !== st.cls) { if (!showSub) continue; }
            col.append(cell(t, cls, covMap));
            if (showSub) for (const sub of SM.FW.subtechniques(t.id).filter(s => (s.tactics || []).includes(tac.id))) { const sc = covMap.get(sub.id); const scl = sc ? sc.classification : 'UNKNOWN'; if (st.platform && !(sub.platforms || []).includes(st.platform)) continue; if (st.cls && scl !== st.cls) continue; const ce = cell(sub, scl, covMap); ce.classList.add('sub'); col.append(ce); }
          }
          grid.append(col);
        }
        m.append(grid);
      }
      function cell(t, cls, covMap) { const c = covMap.get(t.id); const el = h('div', { class: 'tech-cell', dataset: { cov: cls }, title: t.name + ' — ' + SM.COVERAGE[cls].label, onClick: () => SM.matrixPanel(t.id) }, h('span', { class: 'id' }, t.id), h('br'), SM.truncate(t.name, 26)); return el; }
      renderMatrix();
      if (params.focus) setTimeout(() => SM.matrixPanel(params.focus), 120);
    }
  });
  function exportMatrix() { const cov = SM.Store.coverage; if (!cov) return SM.toast('Run assessment first', 'warn'); const layer = { name: 'Sentinel Matrix coverage', versions: { attack: SM.FW.attack.version, navigator: '4.x', layer: '4.5' }, domain: 'enterprise-attack', description: 'Generated by Sentinel Matrix', techniques: cov.results.filter(r => r.classification !== 'NOT_APPLICABLE').map(r => ({ techniqueID: r.technique_id, score: r.composite, color: SM.COV_COLORS[r.classification], comment: SM.COVERAGE[r.classification].label + '; rules: ' + r.rule_ids.length, enabled: true })), gradient: { colors: ['#f0506e', '#f5b942', '#2fd48b'], minValue: 0, maxValue: 100 } }; SM.download('attack-navigator-layer.json', JSON.stringify(layer, null, 1), 'application/json'); SM.toast('Exported ATT&CK Navigator layer', 'ok'); }

  // Shared technique assessment panel (used by matrix + coverage + chain)
  SM.matrixPanel = (techId) => {
    const t = SM.FW.technique(techId); if (!t) return SM.toast('Unknown technique ' + techId, 'warn');
    const cov = SM.Store.coverageFor(techId); const gap = SM.Store.gapFor(techId); const tel = SM.FW.telemetryFor(techId); const rules = SM.Store.rules.filter(r => r.attack_techniques.includes(techId) || (!techId.includes('.') && r.attack_techniques.some(x => x.split('.')[0] === techId)));
    const body = h('div');
    body.append(h('div', { class: 'row', style: { marginBottom: '8px' } }, cov ? ui.covTag(cov.classification) : h('span', { class: 'tag grey' }, 'Not assessed'), h('span', { class: 'tag' }, 'Score ' + (cov ? cov.composite : '—')), h('span', { class: 'tag ' + (cov && cov.confidence === 'high' ? 'green' : 'amber') }, 'Confidence ' + (cov ? cov.confidence : '—')), (t.platforms || []).slice(0, 4).map(p => h('span', { class: 'tag violet' }, p))));
    if (t.description) body.append(h('p', { class: 'small' }, t.description));
    if (cov && cov.reasons.length) body.append(ui.card('Assessment rationale', h('ul', { class: 'small', style: { margin: 0, paddingLeft: '18px' } }, cov.reasons.map(r => h('li', r)))));
    // dimensions
    if (cov) body.append(h('div', { style: { margin: '12px 0' } }, SM.chartHBar(Object.entries(cov.dimensions).map(([k, v]) => ({ label: k, value: v })), { max: 100, unit: '/100' })));
    // telemetry
    body.append(ui.card('Required telemetry', h('div', null,
      h('div', { class: 'small' }, h('strong', 'Data components: '), (tel.components || []).map(c => c.component).join(', ') || '—'),
      h('div', { class: 'small', style: { marginTop: '4px' } }, h('strong', 'Log source types: '), (tel.logSourceTypes || []).map(x => { const avail = SM.Store.telemetry().available.has(x); return h('span', { class: 'tag ' + (avail ? 'green' : 'red') }, SM.FW.logSourceType(x).name); })),
      tel.windowsEventIds.length ? h('div', { class: 'small', style: { marginTop: '4px' } }, h('strong', 'Windows Event IDs: '), tel.windowsEventIds.join(', ')) : null,
      tel.sysmonEventIds.length ? h('div', { class: 'small', style: { marginTop: '4px' } }, h('strong', 'Sysmon: '), tel.sysmonEventIds.join(', ')) : null,
      cov && cov.missing_log_source_types && cov.missing_log_source_types.length ? h('div', { class: 'small', style: { marginTop: '6px', color: 'var(--red)' } }, '⚠ Missing: ' + cov.missing_log_source_types.map(x => SM.FW.logSourceType(x).name).join(', ')) : null
    )));
    // associated rules
    body.append(ui.card('Associated rules (' + rules.length + ')', rules.length ? h('table', { class: 'plain' }, h('tbody', rules.slice(0, 20).map(r => h('tr', h('td', h('a', { href: '#', onClick: e => { e.preventDefault(); SM.App.go('inventory', { focus: r.rule_id }); } }, SM.truncate(r.rule_name, 36))), h('td', h('span', { class: 'tag ' + (r.enabled_status === 'enabled' ? 'green' : 'grey') }, r.enabled_status)), h('td', r.mapping_source === 'inferred' ? h('span', { class: 'tag amber' }, 'inferred') : h('span', { class: 'tag cyan' }, 'explicit')))))) : h('div', { class: 'small muted' }, 'No rules mapped.')));
    // scenarios / D3FEND / CAPEC
    const scen = SM.Scenarios.get(techId);
    if (scen) body.append(ui.card('Known detection scenarios (' + scen.scenarios.length + ')', h('div', null, scen.scenarios.map(s => { const matched = cov && (cov.scenarios_matched || []).includes(s.id); return h('div', { class: 'row spread', style: { padding: '3px 0' } }, h('span', { class: 'small' }, h('span', { class: 'tag ' + (matched ? 'green' : 'red') }, matched ? '✓' : '○'), ' ' + s.name), h('span', { class: 'xs muted' }, s.logic_type)); }), h('button', { class: 'btn sm', style: { marginTop: '8px' }, onClick: () => SM.App.go('generator', { technique: techId }) }, 'Generate rules'))));
    const d3 = SM.FW.d3fendFor(techId); if (d3.length) body.append(ui.card('D3FEND countermeasures', h('div', { class: 'row', style: { gap: '4px' } }, d3.map(d => h('span', { class: 'tag violet', title: d.description }, d.id + ' ' + d.name)))));
    const capec = SM.FW.capecFor(techId); if (capec.length) body.append(ui.card('CAPEC patterns', h('div', { class: 'row', style: { gap: '4px' } }, capec.map(c => h('span', { class: 'tag', title: c.description }, c.id)))));
    if (gap) body.append(ui.card('Gap & recommendation', h('div', null, h('div', { class: 'row', style: { marginBottom: '6px' } }, ui.riskTag(gap.risk_level), h('span', { class: 'tag' }, 'Priority ' + gap.priority_score)), h('ul', { class: 'small', style: { margin: 0, paddingLeft: '18px' } }, gap.recommended_action.map(a => h('li', a))), h('button', { class: 'btn sm', style: { marginTop: '8px' }, onClick: () => SM.App.go('gaps', { focus: techId }) }, 'Open in Gap Analysis'))));
    SM.drawer.open(techId + ' · ' + t.name, body, (t.tactics || []).map(x => SM.FW.tacticName(x)).join(' · '));
  };
})(globalThis.SM = globalThis.SM || {});
