/* SENTINEL MATRIX — Rule Generator + Detection Engineering workbench. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;
  const FORMATS = [['sigma', 'Sigma YAML'], ['splunk', 'Splunk SPL'], ['sentinel', 'Microsoft Sentinel KQL'], ['elastic', 'Elastic KQL/ES|QL'], ['qradar', 'QRadar specification'], ['generic', 'SIEM-neutral spec'], ['json', 'JSON']];
  const MATURITY = { generated_specification: ['Generated specification', 'grey'], syntax_validated: ['Syntax-validated', 'amber'], deployment_ready: ['Deployment-ready', 'cyan'], tested: ['Tested detection', 'green'] };

  SM.registerModule('generator', {
    title: 'Rule Generator', subtitle: 'Deterministic, template-driven detection engineering — multiple scenarios per technique',
    render(body, params, actions) {
      const state = { technique: params.technique || '', platform: 'sigma', environment: SM.Store.activeProfileId, severity: '', generated: null };
      const form = h('div', { class: 'card' });
      const techInput = h('input', { type: 'text', list: 'tech-list', value: state.technique, placeholder: 'T1558.003', onInput: e => state.technique = e.target.value.toUpperCase() });
      const datalist = h('datalist', { id: 'tech-list' }, SM.Scenarios.all().map(s => h('option', { value: s.technique }, s.technique + ' — ' + s.name)));
      const platformSel = h('select', { onChange: e => state.platform = e.target.value }, FORMATS.filter(f => f[0] !== 'json').map(f => h('option', { value: f[0], selected: f[0] === state.platform }, f[1])));
      const envSel = h('select', { onChange: e => state.environment = e.target.value }, (SM.FW.profiles || []).map(p => h('option', { value: p.id, selected: p.id === state.environment }, p.name)));
      const sevSel = h('select', { onChange: e => state.severity = e.target.value }, h('option', { value: '' }, 'Scenario default'), SM.SEVERITIES.map(s => h('option', { value: s }, s)));
      form.append(h('h3', 'Generation inputs'), datalist, h('div', { class: 'form-grid' },
        h('div', { class: 'field' }, h('label', 'ATT&CK technique / sub-technique'), techInput),
        h('div', { class: 'field' }, h('label', 'Target SIEM'), platformSel),
        h('div', { class: 'field' }, h('label', 'Enterprise environment profile'), envSel),
        h('div', { class: 'field' }, h('label', 'Severity override'), sevSel)
      ), h('div', { class: 'row', style: { marginTop: '12px' } },
        h('button', { class: 'btn primary', onClick: generate }, '⚙ Generate scenarios'),
        h('button', { class: 'btn ghost', onClick: () => showUncovered() }, 'Pick an uncovered technique'),
        h('button', { class: 'btn ghost', onClick: customScenario }, '＋ Author custom scenario')
      ));
      body.append(form);
      body.append(h('div', { class: 'small muted', style: { margin: '10px 0' } }, 'Output is a rule SPECIFICATION by default. Maturity is labelled explicitly: ', Object.values(MATURITY).map(([l, c]) => h('span', { class: 'tag ' + c, style: { marginRight: '4px' } }, l)), ' QRadar output is an intentional build specification, not fabricated CRE syntax.'));
      const out = h('div', { id: 'gen-out' }); body.append(out);
      function generate() {
        if (!state.technique) return SM.toast('Enter a technique ID', 'warn');
        const env = SM.FW.profile(state.environment);
        const res = SM.Generator.generateForTechnique(state.technique, { platform: state.platform, environment: env, severity: state.severity || undefined });
        state.generated = res; renderGenerated(out, res, state);
      }
      if (params.technique) generate();
    }
  });

  function renderGenerated(out, res, state) {
    SM.clear(out);
    if (!res.scenarios.length) { out.append(ui.empty('No scenario template for ' + res.technique, res.note || 'Author a custom scenario or map to a parent technique.', h('button', { class: 'btn', onClick: () => customScenario(res.technique) }, 'Author custom scenario'))); return; }
    const t = SM.FW.technique(res.technique);
    out.append(h('div', { class: 'row spread', style: { marginBottom: '10px' } }, h('div', null, h('strong', res.technique + ' — ' + res.technique_name), h('div', { class: 'small muted' }, res.scenarios.length + ' distinct detection scenarios generated for ' + state.platform.toUpperCase())), h('button', { class: 'btn primary', onClick: () => saveAll(res) }, '＋ Add all to engineering workbench')));
    for (const rec of res.scenarios) out.append(scenarioCard(rec, state));
  }
  function scenarioCard(rec, state) {
    const card = h('div', { class: 'card', style: { marginBottom: '12px' } });
    const [ml, mc] = MATURITY[rec.maturity] || MATURITY.generated_specification;
    card.append(h('div', { class: 'row spread' }, h('div', null, h('strong', rec.scenario_name), h('div', { class: 'small muted' }, rec.objective)), h('div', { class: 'row', style: { gap: '4px' } }, h('span', { class: 'tag ' + mc }, ml), ui.sevTag(rec.severity), h('span', { class: 'tag' }, rec.logic_type))));
    card.append(h('div', { class: 'row', style: { gap: '4px', margin: '8px 0' } }, h('span', { class: 'tag cyan' }, rec.technique), (rec.required_telemetry || []).map(x => h('span', { class: 'tag' }, SM.FW.logSourceType(x).name)), rec.event_ids && rec.event_ids.length ? h('span', { class: 'tag violet' }, 'EID ' + rec.event_ids.join(',')) : null));
    // format switcher
    const pre = h('pre'); const setFmt = (fmt) => { const r = SM.Generator.render(rec.spec, fmt); pre.textContent = r.body; }; setFmt(state.platform);
    const fmtRow = h('div', { class: 'tabs', style: { marginBottom: '8px' } }, FORMATS.map(([f, label]) => h('div', { class: 'tab' + (f === state.platform ? ' active' : ''), onClick: e => { SM.$$('.tab', fmtRow).forEach(x => x.classList.remove('active')); e.target.classList.add('active'); setFmt(f); } }, label)));
    card.append(fmtRow, pre);
    // SIEM compatibility + tuning + tests
    card.append(h('details', { class: 'small' }, h('summary', { style: { cursor: 'pointer', margin: '8px 0' } }, 'Telemetry, tuning, false positives & validation test cases'),
      h('div', { class: 'grid c2' },
        h('div', null, h('strong', 'SIEM compatibility'), h('table', { class: 'plain' }, h('tbody', Object.entries(rec.siem_compatibility).map(([k, v]) => h('tr', h('td', k), h('td', v)))))),
        h('div', null, h('strong', 'Tuning guidance'), h('ul', { style: { paddingLeft: '16px', margin: '4px 0' } }, (rec.tuning || []).map(x => h('li', x))), h('strong', 'Known false positives'), h('ul', { style: { paddingLeft: '16px', margin: '4px 0' } }, (rec.false_positives || []).map(x => h('li', x))))
      ),
      h('strong', 'Validation test cases (' + (rec.test_cases || []).length + ')'),
      h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'Expected'), h('th', 'Scenario'))), h('tbody', (rec.test_cases || []).map(tc => h('tr', h('td', h('span', { class: 'tag ' + (tc.expected === 'match' ? 'green' : 'grey') }, tc.expected)), h('td', tc.name)))))
    ));
    card.append(h('div', { class: 'row', style: { marginTop: '10px' } },
      h('button', { class: 'btn sm', onClick: () => { const r = SM.Generator.render(rec.spec, SM.$('.tab.active', fmtRow) ? FORMATS.find(f => SM.$('.tab.active', fmtRow).textContent === f[1])[0] : state.platform); SM.download(SM.slug(rec.scenario_name) + '.' + ({ yaml: 'yml', spl: 'spl', kql: 'kql', text: 'txt', json: 'json' }[r.lang] || 'txt'), r.body, 'text/plain'); } }, '⬇ Export'),
      h('button', { class: 'btn sm', onClick: () => { navigator.clipboard && navigator.clipboard.writeText(pre.textContent).then(() => SM.toast('Copied', 'ok')).catch(() => SM.toast('Copy unavailable', 'warn')); } }, 'Copy'),
      h('button', { class: 'btn sm primary', onClick: () => saveOne(rec) }, '＋ Add to workbench'),
      h('button', { class: 'btn sm ghost', onClick: () => SM.App.go('validation', { generated: rec.id, scenario: JSON.stringify(rec.test_cases) }) }, 'Validate')
    ));
    return card;
  }
  async function saveOne(rec) { await SM.Store.saveGenerated([rec]); await SM.Store.addLifecycleEvent({ rule_id: rec.id, from: null, to: 'Proposed', note: 'Generated specification for ' + rec.technique, author: SM.Store.settings.analyst || 'analyst' }); SM.toast('Added "' + rec.scenario_name + '" to the engineering workbench (Proposed)', 'ok'); }
  async function saveAll(res) { await SM.Store.saveGenerated(res.scenarios); for (const rec of res.scenarios) await SM.Store.addLifecycleEvent({ rule_id: rec.id, from: null, to: 'Proposed', note: 'Generated specification', author: SM.Store.settings.analyst || 'analyst' }); SM.toast('Added ' + res.scenarios.length + ' scenarios to the workbench', 'ok'); SM.App.go('engineering'); }

  function showUncovered() {
    const cov = SM.Store.coverage; if (!cov) return SM.toast('Run a coverage assessment first', 'warn');
    const list = cov.results.filter(r => ['NOT_COVERED', 'WEAK_COVERAGE'].includes(r.classification) && SM.Scenarios.has(r.technique_id)).sort((a, b) => (SM.Store.gapFor(b.technique_id) ? SM.Store.gapFor(b.technique_id).priority_score : 0) - (SM.Store.gapFor(a.technique_id) ? SM.Store.gapFor(a.technique_id).priority_score : 0));
    SM.modal({ title: 'Uncovered techniques with scenario templates', body: list.length ? h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'Technique'), h('th', 'Coverage'), h('th', 'Scenarios'), h('th', ''))), h('tbody', list.slice(0, 40).map(r => h('tr', h('td', r.technique_id + ' ' + SM.truncate(r.technique_name, 26)), h('td', ui.covTag(r.classification)), h('td', SM.Scenarios.get(r.technique_id).scenarios.length), h('td', h('button', { class: 'btn sm', onClick: () => { SM.$('#modal-back').classList.remove('open'); SM.App.go('generator', { technique: r.technique_id }); } }, 'Generate')))))) : h('div', { class: 'empty' }, 'All templated techniques are covered.') });
  }
  function customScenario(technique) {
    technique = typeof technique === 'string' ? technique : '';
    const f = { technique, name: '', objective: '', logic_type: 'threshold', severity: 'medium', log_sources: '', event_ids: '', keywords: '', conditions: '' };
    const fld = (label, key, ph) => h('div', { class: 'field' }, h('label', label), h('input', { type: 'text', value: f[key], placeholder: ph, onInput: e => f[key] = e.target.value }));
    SM.modal({ title: 'Author custom detection scenario', wide: true, body: h('div', { class: 'form-grid' },
      fld('ATT&CK technique', 'technique', 'T1234'), fld('Scenario name', 'name', 'Anomalous X behaviour'),
      h('div', { class: 'field', style: { gridColumn: '1 / -1' } }, h('label', 'Detection objective'), h('input', { type: 'text', onInput: e => f.objective = e.target.value })),
      h('div', { class: 'field' }, h('label', 'Logic type'), h('select', { onChange: e => f.logic_type = e.target.value }, ['threshold', 'frequency', 'sequence', 'correlation', 'behavioural', 'baseline', 'multi_source', 'entity', 'time_based', 'statistical', 'process', 'state_change'].map(x => h('option', { value: x }, x)))),
      h('div', { class: 'field' }, h('label', 'Severity'), h('select', { onChange: e => f.severity = e.target.value }, SM.SEVERITIES.map(s => h('option', { value: s, selected: s === 'medium' }, s)))),
      fld('Log source types (comma)', 'log_sources', 'windows_security, sysmon'), fld('Event IDs (comma)', 'event_ids', '4769, 4624'),
      fld('Keywords (comma)', 'keywords', 'kerberoast, 4769'),
      h('div', { class: 'field', style: { gridColumn: '1 / -1' } }, h('label', 'Field conditions — one per line: field op value  (op: eq, contains, endswith, ne, gt, in[|])'), h('textarea', { placeholder: 'EventID eq 4769\nServiceName ne krbtgt', onInput: e => f.conditions = e.target.value }))
    ), footer: close => [h('button', { class: 'btn', onClick: close }, 'Cancel'), h('button', { class: 'btn primary', onClick: async () => {
      if (!f.technique || !f.name) return SM.toast('Technique and name required', 'warn');
      const selection = f.conditions.split('\n').map(l => l.trim()).filter(Boolean).map(l => { const m = l.match(/^(\S+)\s+(eq|contains|endswith|ne|gt|in|contains_any|endswith_any|not_in)\s+(.+)$/); if (!m) return null; let v = m[3]; if (m[2] === 'in' || m[2].endsWith('_any') || m[2] === 'not_in') v = v.split('|').map(x => x.trim()); else if (/^\d+$/.test(v)) v = parseInt(v, 10); return { field: m[1], op: m[2], value: v }; }).filter(Boolean);
      const sc = { name: f.name, objective: f.objective || f.name, logic_type: f.logic_type, severity: f.severity, keywords: f.keywords.split(',').map(x => x.trim()).filter(Boolean), event_ids: f.event_ids.split(',').map(x => parseInt(x, 10)).filter(x => !isNaN(x)), log_source_types: f.log_sources.split(',').map(x => x.trim()).filter(Boolean), selection, exclusions: [], agg: null, fp: ['Define based on environment'], tuning: ['Baseline before enabling'], tests: [] };
      await SM.Scenarios.addCustom(f.technique, SM.FW.technique(f.technique) ? SM.FW.technique(f.technique).name : f.technique, sc);
      SM.toast('Custom scenario saved for ' + f.technique, 'ok'); close(); SM.App.go('generator', { technique: f.technique });
    } }, 'Save scenario')] });
  }

  // ---------------- Detection Engineering workbench ----------------
  SM.registerModule('engineering', {
    title: 'Detection Engineering', subtitle: 'Workbench of generated and draft detections',
    render(body, params, actions) {
      actions.append(h('button', { class: 'btn primary', onClick: () => SM.App.go('generator') }, '⚙ Open generator'), h('button', { class: 'btn ghost', onClick: exportWorkbench }, '⬇ Export all'));
      const recs = SM.Store.generated;
      if (!recs.length) { body.append(ui.empty('Workbench empty', 'Generate detection specifications and add them here to manage them through the lifecycle.', h('button', { class: 'btn primary', onClick: () => SM.App.go('generator') }, 'Generate rules'))); return; }
      body.append(h('div', { class: 'grid kpi' },
        ui.kpi('Proposed detections', recs.length, { color: 'cyan' }),
        ui.kpi('Techniques addressed', SM.uniq(recs.map(r => r.technique)).length),
        ui.kpi('Target platforms', SM.uniq(recs.map(r => r.target_platform)).length),
        ui.kpi('With test cases', recs.filter(r => r.test_cases && r.test_cases.length).length, { color: 'green' })
      ));
      const table = SM.VTable([
        { key: 'scenario_name', label: 'Detection', width: '2.2fr', render: r => h('div', null, h('div', r.scenario_name), h('div', { class: 'xs muted' }, r.technique + ' · ' + r.technique_name)) },
        { key: 'target_platform', label: 'Platform', width: '0.9fr', render: r => h('span', { class: 'tag' }, r.target_platform) },
        { key: 'logic_type', label: 'Logic', width: '1fr', render: r => h('span', { class: 'xs muted' }, r.logic_type) },
        { key: 'severity', label: 'Severity', width: '0.8fr', render: r => ui.sevTag(r.severity) },
        { key: 'lifecycle_stage', label: 'Stage', width: '1fr', render: r => h('span', { class: 'tag ' + (r.lifecycle_stage === 'Validated' || r.lifecycle_stage === 'Operational' ? 'green' : 'cyan') }, r.lifecycle_stage) },
        { key: 'maturity', label: 'Maturity', width: '1.2fr', render: r => { const [l, c] = MATURITY[r.maturity] || MATURITY.generated_specification; return h('span', { class: 'tag ' + c }, l); } }
      ], { idKey: 'id', maxHeight: 520, sortKey: 'scenario_name', sortDir: 1, onRow: r => openGenerated(r) });
      body.append(table.el); table.setRows(recs);
    }
  });
  function openGenerated(rec) {
    const body = h('div');
    const pre = h('pre', rec.rendered_body);
    const fmtRow = h('div', { class: 'tabs', style: { marginBottom: '8px' } }, FORMATS.map(([f, label]) => h('div', { class: 'tab' + (f === rec.rendered_format ? ' active' : ''), onClick: e => { SM.$$('.tab', fmtRow).forEach(x => x.classList.remove('active')); e.target.classList.add('active'); pre.textContent = SM.Generator.render(rec.spec, f).body; } }, label)));
    body.append(h('div', { class: 'row', style: { marginBottom: '8px' } }, h('span', { class: 'tag cyan' }, rec.technique), ui.sevTag(rec.severity), h('span', { class: 'tag' }, rec.lifecycle_stage)), fmtRow, pre);
    body.append(h('h3', { style: { marginTop: '12px' } }, 'Lifecycle'), SM.lifecycleControl(rec));
    SM.drawer.open(rec.scenario_name, body, rec.technique + ' · ' + rec.objective);
  }
  function exportWorkbench() { const recs = SM.Store.generated; if (!recs.length) return; SM.download('generated-detections.json', JSON.stringify(recs.map(r => ({ id: r.id, technique: r.technique, scenario: r.scenario_name, platform: r.target_platform, severity: r.severity, lifecycle: r.lifecycle_stage, maturity: r.maturity, body: r.rendered_body })), null, 1), 'application/json'); }
})(globalThis.SM = globalThis.SM || {});
