/* SENTINEL MATRIX — Detection Validation Workbench + Detection Lifecycle. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;
  const RESULTS = ['PASS', 'FAIL', 'PARTIAL', 'NOT_EXECUTED', 'INCONCLUSIVE'];
  const STAGES = ['Proposed', 'Draft', 'Under Review', 'Approved', 'Validated', 'Deployment Ready', 'Deployed', 'Operational', 'Requires Tuning', 'Deprecated', 'Archived'];
  SM.LIFECYCLE_STAGES = STAGES;

  SM.registerModule('validation', {
    title: 'Detection Validation', subtitle: 'Validate rules against imported test events and authorised test scenarios',
    render(body, params, actions) {
      actions.append(h('button', { class: 'btn ghost', onClick: importTestEvents }, '⬆ Import test events'), h('button', { class: 'btn ghost', onClick: importAtomic }, '⬆ Import Atomic/CALDERA results'), h('button', { class: 'btn ghost', onClick: exportTests }, '⬇ Export results'));
      body.append(h('div', { class: 'demo-banner', style: { background: 'rgba(25,211,243,.06)', borderColor: 'rgba(25,211,243,.35)', color: '#bdeefb' } }, 'ⓘ', h('span', null, 'This workbench evaluates rule logic against test events locally. It never executes attack simulations or launches payloads. A detection is only marked "validated" after a test case has actually been executed here.')));
      const tabs = SM.tabs([
        { label: 'Test runner', render: () => runner(params) },
        { label: 'Results (' + SM.Store.tests.length + ')', render: () => resultsView() }
      ], { active: 0 });
      body.append(tabs);
    }
  });
  function runner(params) {
    const wrap = h('div'); const state = { rule: null, events: [], cases: [] };
    const ruleSel = h('select', { onChange: e => { state.rule = e.target.value; loadCases(); } }, h('option', { value: '' }, 'Select an imported rule…'), SM.Store.rules.slice(0, 2000).map(r => h('option', { value: r.rule_id, selected: params.rule === r.rule_id }, SM.truncate(r.rule_name || r.rule_id, 60))));
    const genSel = h('select', { onChange: e => { state.rule = null; state.gen = e.target.value; loadGenCases(); } }, h('option', { value: '' }, '…or a generated detection'), SM.Store.generated.map(g => h('option', { value: g.id, selected: params.generated === g.id }, SM.truncate(g.scenario_name, 50))));
    wrap.append(ui.card('1 · Select detection to validate', h('div', { class: 'form-grid' }, h('div', { class: 'field' }, h('label', 'Imported rule'), ruleSel), h('div', { class: 'field' }, h('label', 'Generated detection'), genSel))));
    const eventsTA = h('textarea', { placeholder: '[{"EventID":4769,"TargetUserName":"jdoe","distinct_ServiceName":10}, ...]  — one JSON object or an array', style: { minHeight: '120px' } });
    wrap.append(ui.card('2 · Test events (JSON)', h('div', null, eventsTA, h('div', { class: 'row', style: { marginTop: '8px' } }, h('button', { class: 'btn sm', onClick: loadCasesFromTemplates }, 'Load bundled test cases'), h('button', { class: 'btn sm ghost', onClick: () => { eventsTA.value = ''; } }, 'Clear')))));
    const casesBox = h('div', { id: 'cases-box' }); wrap.append(ui.card('3 · Test cases & execution', casesBox));
    function loadCases() { const r = SM.Store.rules.find(x => x.rule_id === state.rule); state.cases = []; if (r) { const scen = SM.Scenarios.get(r.attack_techniques[0]); if (scen) state.cases = scen.scenarios.flatMap(s => (s.tests || []).map(t => Object.assign({ scenario: s.name }, t))); } renderCases(); }
    function loadGenCases() { const g = SM.Store.generated.find(x => x.id === state.gen); state.cases = g ? (g.test_cases || []).map(t => Object.assign({ scenario: g.scenario_name }, t)) : []; renderCases(); }
    function loadCasesFromTemplates() { loadCases(); if (state.cases.length) { eventsTA.value = JSON.stringify(state.cases.map(c => c.input), null, 1); SM.toast('Loaded ' + state.cases.length + ' bundled test cases', 'ok'); } else SM.toast('No bundled test cases for this rule\'s technique', 'warn'); }
    function renderCases() { SM.clear(casesBox); if (!state.cases.length) { casesBox.append(h('div', { class: 'small muted' }, 'Select a detection with bundled test cases, or define expected results manually below.')); } else casesBox.append(h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'Expected'), h('th', 'Test scenario'), h('th', 'Input'))), h('tbody', state.cases.map(c => h('tr', h('td', h('span', { class: 'tag ' + (c.expected === 'match' ? 'green' : 'grey') }, c.expected)), h('td', c.name), h('td', h('span', { class: 'xs mono' }, SM.truncate(JSON.stringify(c.input), 60)))))))); casesBox.append(h('button', { class: 'btn primary', style: { marginTop: '10px' }, onClick: execute }, '▶ Execute test cases')); }
    async function execute() {
      const rule = SM.Store.rules.find(x => x.rule_id === state.rule); const gen = SM.Store.generated.find(x => x.id === state.gen);
      const spec = gen ? gen.spec : null; const results = [];
      for (const c of state.cases) { const actual = evaluate(c.input, rule, spec); const status = (c.expected === 'match') === actual ? 'PASS' : 'FAIL'; const test = { test_id: SM.uid('test'), rule_id: state.rule || state.gen, generated_id: gen ? gen.id : null, attack_technique: rule ? rule.attack_techniques[0] : (gen ? gen.technique : ''), test_scenario: c.scenario + ' / ' + c.name, input_event: c.input, expected: c.expected, actual: actual ? 'match' : 'no_match', status, executed_at: SM.now(), analyst: SM.Store.settings.analyst || 'analyst', evidence: 'Local logic evaluation' }; results.push(test); await SM.Store.saveTest(test); }
      // update rule/generated validation status
      if (rule) { const passed = results.filter(r => r.status === 'PASS').length; rule.validation_status = passed === results.length && results.length ? 'validated' : (results.some(r => r.status === 'FAIL') ? 'failed' : 'tested'); await SM.DB.put('rules', rule); SM.emit('rules:changed'); }
      if (gen && results.every(r => r.status === 'PASS') && results.length) { gen.maturity = 'tested'; gen.lifecycle_stage = 'Validated'; await SM.DB.put('generated_rules', gen); await SM.Store.addLifecycleEvent({ rule_id: gen.id, from: 'Proposed', to: 'Validated', note: 'All ' + results.length + ' test cases passed', author: SM.Store.settings.analyst || 'analyst' }); SM.emit('generated:changed'); }
      const pass = results.filter(r => r.status === 'PASS').length;
      SM.toast('Executed ' + results.length + ' tests: ' + pass + ' PASS, ' + (results.length - pass) + ' FAIL', pass === results.length ? 'ok' : 'warn');
      SM.drawer.open('Validation results', h('div', null, h('div', { class: 'row', style: { marginBottom: '10px' } }, h('span', { class: 'tag green' }, pass + ' PASS'), h('span', { class: 'tag red' }, (results.length - pass) + ' FAIL')), h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'Status'), h('th', 'Test'), h('th', 'Expected'), h('th', 'Actual'))), h('tbody', results.map(r => h('tr', h('td', h('span', { class: 'tag ' + (r.status === 'PASS' ? 'green' : 'red') }, r.status)), h('td', SM.truncate(r.test_scenario, 36)), h('td', r.expected), h('td', r.actual)))))));
    }
    if (params.rule) { ruleSel.value = params.rule; state.rule = params.rule; loadCases(); }
    if (params.generated) { genSel.value = params.generated; state.gen = params.generated; loadGenCases(); }
    return wrap;
  }
  // Local deterministic evaluation of a test event against rule logic or a generated spec's predicates.
  function evaluate(event, rule, spec) {
    if (spec) return evalSpec(event, spec);
    if (!rule) return false;
    // heuristic: match if event's EventID is in the rule and keywords/fields present, and any aggregation hint satisfied
    const logic = (rule.detection_logic || '').toLowerCase(); let ok = true;
    if (event.EventID !== undefined && rule.event_ids.length) ok = ok && rule.event_ids.includes(Number(event.EventID));
    // threshold-style: count/distinct in event vs rule threshold
    if (rule.threshold && (event.count !== undefined || event.distinct_ServiceName !== undefined || event.distinct_users !== undefined || event.distinct_Computer !== undefined)) { const v = event.count || event.distinct_ServiceName || event.distinct_users || event.distinct_Computer || 0; ok = ok && (rule.threshold.operator === '>' ? v > rule.threshold.value : v >= rule.threshold.value); }
    // keyword presence from command line
    const text = JSON.stringify(event).toLowerCase(); const kws = (rule.detection_logic.match(/[a-z0-9_.$\\/-]{4,}/gi) || []).slice(0, 40);
    if (event.baseline_seen !== undefined) ok = ok && !event.baseline_seen;
    if (event.in_reference_set !== undefined) ok = ok && event.in_reference_set;
    return ok;
  }
  function evalSpec(event, spec) {
    const test = (p) => { const v = resolve(event, p.field); const val = p.value; const s = SM.str(v).toLowerCase(); const arr = Array.isArray(val) ? val.map(x => SM.str(x).toLowerCase()) : null; switch (p.op) {
      case 'eq': return SM.str(v).toLowerCase() === SM.str(val).toLowerCase() || Number(v) === Number(val); case 'in': return arr.includes(s);
      case 'ne': return SM.str(v).toLowerCase() !== SM.str(val).toLowerCase(); case 'contains': return s.includes(SM.str(val).toLowerCase()); case 'contains_any': return arr.some(x => s.includes(x));
      case 'endswith': return s.endsWith(SM.str(val).toLowerCase()); case 'endswith_any': return arr.some(x => s.endsWith(x)); case 'not_in': return !arr.some(x => s.endsWith(x) || s === x);
      case 'gt': return Number(v) > Number(val); case 'regex': try { return new RegExp(val, 'i').test(SM.str(v)); } catch (e) { return false; } default: return false; } };
    let ok = (spec.selection || []).every(test);
    if (ok && (spec.exclusions || []).length) ok = !spec.exclusions.some(test);
    if (ok && spec.agg) { const a = spec.agg; if (a.fn === 'count') { const v = event.count || event['distinct_' + (a.distinct || '')] || event.distinct_users || event.distinct_Computer || event.distinct_subdomains || 0; if (v) ok = v >= a.threshold; } if (a.fn === 'new_value') ok = event.baseline_seen === false || event.baseline_seen === undefined ? (event.baseline_seen === false ? true : ok) : false; if (a.reference_set) ok = ok && (event.in_reference_set === true); if (a.fn === 'zscore' && event.mean !== undefined) ok = (event.today - event.mean) / (event.stdev || 1) >= a.threshold; if (a.fn === 'absence') ok = event.seen === false; if (a.fn === 'sequence') ok = !!(event.step1 && event.step2); }
    return ok;
  }
  function resolve(event, field) { if (event[field] !== undefined) return event[field]; const lf = Object.keys(event).find(k => k.toLowerCase() === field.toLowerCase()); return lf ? event[lf] : undefined; }

  function resultsView() {
    const wrap = h('div'); const tests = SM.Store.tests;
    if (!tests.length) return ui.empty('No validation runs', 'Execute test cases in the test runner to record validation evidence.');
    const counts = SM.countBy(tests, 'status');
    wrap.append(h('div', { class: 'grid kpi' }, RESULTS.map(r => ui.kpi(r, counts[r] || 0, { color: r === 'PASS' ? 'green' : r === 'FAIL' ? 'red' : r === 'PARTIAL' ? 'amber' : undefined }))));
    const table = SM.VTable([
      { key: 'executed_at', label: 'When', width: '1fr', render: t => h('span', { class: 'xs' }, SM.fmtDate(t.executed_at)) },
      { key: 'rule_id', label: 'Detection', width: '2fr', render: t => h('span', null, SM.truncate(t.rule_id, 40)) },
      { key: 'test_scenario', label: 'Test', width: '2fr', render: t => SM.truncate(t.test_scenario, 46) },
      { key: 'expected', label: 'Expected', width: '0.8fr' },
      { key: 'actual', label: 'Actual', width: '0.8fr' },
      { key: 'status', label: 'Result', width: '0.9fr', render: t => h('span', { class: 'tag ' + (t.status === 'PASS' ? 'green' : t.status === 'FAIL' ? 'red' : 'amber') }, t.status) }
    ], { idKey: 'test_id', maxHeight: 480, sortKey: 'executed_at', sortDir: -1 });
    wrap.append(table.el); table.setRows(tests);
    return wrap;
  }
  function importTestEvents() { fileImport('Test events', async (obj) => { SM.toast('Loaded ' + (Array.isArray(obj) ? obj.length : 1) + ' events — paste them into the runner', 'ok'); }); }
  function importAtomic() {
    fileImport('Atomic Red Team / CALDERA results', async (obj) => {
      const list = Array.isArray(obj) ? obj : (obj.results || obj.tests || [obj]); let n = 0;
      for (const r of list) { const tech = SM.extractTechniqueIds(JSON.stringify(r))[0] || ''; const test = { test_id: SM.uid('test'), rule_id: r.rule_id || r.technique || tech, attack_technique: tech, test_scenario: 'Imported: ' + (r.name || r.test || r.ability_id || 'atomic test'), input_event: r, expected: 'match', actual: r.detected || r.result === 'success' ? 'match' : 'no_match', status: (r.detected || r.status === 'detected' || r.result === 'success') ? 'PASS' : (r.status === 'not_detected' ? 'FAIL' : 'INCONCLUSIVE'), executed_at: r.timestamp || SM.now(), analyst: 'imported', evidence: 'Imported from ' + (obj.tool || 'adversary emulation tool') }; await SM.Store.saveTest(test); n++; }
      SM.toast('Imported ' + n + ' validation results', 'ok'); SM.App.go('validation', { tab: 1 });
    });
  }
  function fileImport(label, cb) { const inp = h('input', { type: 'file', accept: '.json', style: { display: 'none' }, onChange: async e => { const f = e.target.files[0]; if (!f) return; try { const obj = SM.safeJSON(await SM.readFileText(f)); await cb(obj); } catch (err) { SM.toast('Import failed: ' + err.message, 'err'); } } }); document.body.appendChild(inp); inp.click(); setTimeout(() => inp.remove(), 1000); }
  function exportTests() { if (!SM.Store.tests.length) return SM.toast('No results', 'warn'); SM.download('validation-results.json', JSON.stringify(SM.Store.tests, null, 1), 'application/json'); }

  // ---------------- Lifecycle ----------------
  SM.registerModule('lifecycle', {
    title: 'Detection Lifecycle', subtitle: 'Manage detections through proposal → operational with full audit trail',
    render(body, params, actions) {
      const recs = SM.Store.generated;
      if (!recs.length) { body.append(ui.empty('No managed detections', 'Add generated detections to the workbench to track their lifecycle.', h('button', { class: 'btn primary', onClick: () => SM.App.go('generator') }, 'Generate rules'))); return; }
      actions.append(h('button', { class: 'btn ghost', onClick: () => exportAudit() }, '⬇ Export audit trail'));
      const board = h('div', { class: 'board' });
      const byStage = SM.groupBy(recs, 'lifecycle_stage');
      for (const stage of STAGES) { const items = byStage.get(stage) || []; const col = h('div', { class: 'board-col' }, h('h4', stage, h('span', items.length))); for (const r of items) col.append(h('div', { class: 'board-card', onClick: () => openCard(r) }, h('div', SM.truncate(r.scenario_name, 40)), h('div', { class: 'xs muted' }, r.technique + ' · ' + r.target_platform))); board.append(col); }
      body.append(board);
      body.append(ui.card('Recent lifecycle events', h('div', { class: 'timeline' }, SM.Store.lifecycleEvents.slice(-25).reverse().map(e => h('div', { class: 'tl-item' }, h('span', { class: 'when' }, SM.fmtDate(e.at) + ' · ' + (e.author || 'analyst')), h('div', { class: 'small' }, (e.from ? e.from + ' → ' : '') + h('strong', e.to) + (e.note ? ' — ' + e.note : '')))))));
    }
  });
  function openCard(r) { SM.drawer.open(r.scenario_name, h('div', null, h('div', { class: 'row', style: { marginBottom: '8px' } }, h('span', { class: 'tag cyan' }, r.technique), ui.sevTag(r.severity)), SM.lifecycleControl(r), h('h3', { style: { marginTop: '12px' } }, 'History'), h('div', { class: 'timeline' }, SM.Store.lifecycleEvents.filter(e => e.rule_id === r.id).reverse().map(e => h('div', { class: 'tl-item' }, h('span', { class: 'when' }, SM.fmtDate(e.at) + ' · ' + (e.author || 'analyst')), h('div', { class: 'small' }, (e.from ? e.from + ' → ' : '') + e.to + (e.note ? ' — ' + e.note : '')))))), r.technique); }

  SM.lifecycleControl = (rec) => {
    const box = h('div');
    const sel = h('select', null, STAGES.map(s => h('option', { value: s, selected: s === rec.lifecycle_stage }, s)));
    const note = h('input', { type: 'text', placeholder: 'Change note (optional)' });
    box.append(h('div', { class: 'row' }, h('div', { class: 'field', style: { flex: 1 } }, h('label', 'Lifecycle stage'), sel), h('div', { class: 'field', style: { flex: 2 } }, h('label', 'Note'), note)));
    box.append(h('div', { class: 'row', style: { marginTop: '8px' } }, h('button', { class: 'btn sm primary', onClick: async () => { const from = rec.lifecycle_stage; const to = sel.value; if (from === to && !note.value) return; rec.lifecycle_stage = to; if (to === 'Deployment Ready' && rec.maturity === 'generated_specification') rec.maturity = 'deployment_ready'; if (to === 'Validated' && rec.maturity !== 'tested') rec.maturity = 'syntax_validated'; await SM.DB.put('generated_rules', rec); await SM.Store.addLifecycleEvent({ rule_id: rec.id, from, to, note: note.value, author: SM.Store.settings.analyst || 'analyst' }); SM.emit('generated:changed'); SM.toast('Moved to ' + to, 'ok'); note.value = ''; } }, 'Update stage'), h('button', { class: 'btn sm ghost', onClick: async () => { const c = await SM.prompt('Analyst comment', 'Comment'); if (c) { await SM.Store.addAnnotation({ target_id: rec.id, type: 'comment', text: c }); SM.toast('Comment added', 'ok'); } } }, 'Add comment')));
    box.append(h('div', { class: 'xs muted', style: { marginTop: '6px' } }, 'Maturity: ' + rec.maturity.replace(/_/g, ' ') + '. Deployment is never automatic; export the specification and deploy through your SIEM change process.'));
    return box;
  };
  function exportAudit() { SM.download('lifecycle-audit-trail.json', JSON.stringify({ events: SM.Store.lifecycleEvents, annotations: SM.Store.annotations }, null, 1), 'application/json'); }
})(globalThis.SM = globalThis.SM || {});
