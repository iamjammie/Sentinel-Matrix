/* SENTINEL MATRIX — Rule Import & Inventory module. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;
  let pendingImport = null; // { files, results, rules, quality }

  SM.registerModule('inventory', {
    title: 'Rule Import & Inventory', subtitle: 'Ingest, normalise and inspect SIEM detection rules',
    render(body, params, actions) {
      actions.append(
        h('button', { class: 'btn', onClick: () => SM.App.go('inventory', { tab: 'import' }) }, '⬆ Import rules'),
        h('button', { class: 'btn ghost', onClick: exportInventory }, '⬇ Export inventory'),
        h('button', { class: 'btn ghost', onClick: loadDemo }, 'Load demo rules')
      );
      const tabs = SM.tabs([
        { label: 'Inventory (' + SM.fmtNum(SM.Store.rules.length) + ')', render: () => inventoryView(params) },
        { label: 'Import workflow', render: () => importView() },
        { label: 'Import batches', render: () => batchesView() }
      ], { active: params.tab === 'import' ? 1 : 0 });
      body.appendChild(ui.demoBanner() || document.createComment(''));
      body.appendChild(tabs);
    }
  });

  function inventoryView(params) {
    const wrap = h('div');
    if (!SM.Store.rules.length) return ui.empty('No rules imported yet', 'Import SIEM rules (JSON, CSV, Sigma YAML, QRadar XML, Splunk/Elastic/Sentinel exports) to begin the assessment.', h('button', { class: 'btn primary', onClick: () => SM.App.go('inventory', { tab: 'import' }) }, 'Start import'));
    const state = { platform: '', severity: '', enabled: '', mapping: '', query: '', flag: '' };
    const filterbar = h('div', { class: 'filterbar' });
    const mk = (label, key, opts) => { const sel = h('select', { onChange: (e) => { state[key] = e.target.value; apply(); } }, h('option', { value: '' }, label), opts.map(o => h('option', { value: o.v }, o.l))); return h('div', { class: 'field' }, h('label', label), sel); };
    const search = h('input', { type: 'text', placeholder: 'Search / filter:  technique:T1558 AND platform:qradar NOT disabled', value: params.focus || '', onInput: (e) => { state.query = e.target.value; apply(); } });
    filterbar.append(
      h('div', { class: 'field', style: { flex: '2', minWidth: '240px' } }, h('label', 'Advanced filter'), search),
      mk('Platform', 'platform', SM.uniq(SM.Store.rules.map(r => r.source_platform)).map(p => ({ v: p, l: p }))),
      mk('Severity', 'severity', SM.SEVERITIES.map(s => ({ v: s, l: s }))),
      mk('State', 'enabled', [{ v: 'enabled', l: 'enabled' }, { v: 'disabled', l: 'disabled' }, { v: 'unknown', l: 'unknown' }]),
      mk('Mapping', 'mapping', [{ v: 'explicit', l: 'explicit' }, { v: 'inferred', l: 'inferred only' }, { v: 'none', l: 'unmapped' }]),
      mk('Quality flag', 'flag', [{ v: 'missing_description', l: 'missing description' }, { v: 'missing_mapping', l: 'missing mapping' }, { v: 'malformed_or_missing_logic', l: 'malformed logic' }, { v: 'unknown_log_source', l: 'unknown log source' }]),
      h('button', { class: 'btn sm', onClick: saveCurrentFilter }, '★ Save filter')
    );
    wrap.appendChild(filterbar);
    if (SM.Store.savedFilters.length) wrap.appendChild(h('div', { class: 'row', style: { marginBottom: '10px' } }, h('span', { class: 'xs muted' }, 'Saved:'), SM.Store.savedFilters.map(f => h('span', { class: 'tag cyan', style: { cursor: 'pointer' }, onClick: () => { search.value = f.query || ''; Object.assign(state, f.state || {}); apply(); } }, f.name, h('span', { style: { marginLeft: '6px', cursor: 'pointer' }, onClick: (e) => { e.stopPropagation(); SM.Store.deleteFilter(f.id).then(() => SM.App.go('inventory')); } }, '✕')))));

    const table = SM.VTable([
      { key: 'rule_name', label: 'Rule', width: '2.4fr', render: r => h('div', null, h('div', SM.truncate(r.rule_name || r.rule_id, 54)), h('div', { class: 'xs muted mono' }, SM.truncate(r.rule_id, 40))) },
      { key: 'source_platform', label: 'Platform', width: '0.8fr', render: r => h('span', { class: 'tag' }, r.source_platform) },
      { key: 'enabled_status', label: 'State', width: '0.7fr', render: r => h('span', { class: 'tag ' + (r.enabled_status === 'enabled' ? 'green' : r.enabled_status === 'disabled' ? 'grey' : 'amber') }, r.enabled_status) },
      { key: 'severity', label: 'Severity', width: '0.8fr', sort: (a, b) => SM.SEVERITIES.indexOf(b.severity) - SM.SEVERITIES.indexOf(a.severity), render: r => ui.sevTag(r.severity) },
      { key: 'attack_techniques', label: 'ATT&CK', width: '1.3fr', render: r => r.attack_techniques.length ? h('div', { class: 'row', style: { gap: '3px' } }, r.attack_techniques.slice(0, 3).map(t => h('span', { class: 'tag cyan' + (r.inferred_techniques.includes(t) ? ' inferred' : '') }, t)), r.attack_techniques.length > 3 ? h('span', { class: 'xs muted' }, '+' + (r.attack_techniques.length - 3)) : null) : h('span', { class: 'tag red' }, 'unmapped') },
      { key: 'log_source_types', label: 'Log sources', width: '1.2fr', render: r => h('span', { class: 'xs muted' }, r.log_source_types.join(', ') || '—') },
      { key: 'quality_flags', label: 'Flags', width: '0.7fr', sort: (a, b) => a.quality_flags.length - b.quality_flags.length, render: r => r.quality_flags.length ? h('span', { class: 'tag ' + (r.quality_flags.length > 2 ? 'red' : 'amber') }, r.quality_flags.length) : h('span', { class: 'tag green' }, '0') }
    ], { idKey: 'rule_id', maxHeight: 560, onRow: openRule, sortKey: 'severity', footExtra: (sorted) => h('span', null, h('button', { class: 'btn sm ghost', onClick: () => exportRows(sorted) }, 'Export ' + SM.fmtNum(sorted.length) + ' filtered')) });
    wrap.appendChild(table.el);
    function apply() { let rows = SM.Store.rules; if (state.platform) rows = rows.filter(r => r.source_platform === state.platform); if (state.severity) rows = rows.filter(r => r.severity === state.severity); if (state.enabled) rows = rows.filter(r => r.enabled_status === state.enabled); if (state.mapping === 'explicit') rows = rows.filter(r => r.mapping_source.startsWith('explicit') || r.mapping_source === 'text-reference'); else if (state.mapping === 'inferred') rows = rows.filter(r => r.mapping_source === 'inferred'); else if (state.mapping === 'none') rows = rows.filter(r => !r.attack_techniques.length); if (state.flag) rows = rows.filter(r => r.quality_flags.includes(state.flag)); if (state.query) rows = SM.Search.filter(rows, state.query); table.setRows(rows, SM.Store.rules.length); }
    apply(); if (params.focus) { setTimeout(() => { const r = SM.Store.rules.find(x => x.rule_id === params.focus); if (r) openRule(r); }, 100); }
    return wrap;
  }

  function openRule(r) {
    const tel = SM.Store.telemetry(); const q = SM.Quality.assess(r, { telemetry: tel, alertStats: SM.Store.alertStats(), testsByRule: SM.Store.testsByRule(), weights: SM.Store.weights.quality });
    const body = h('div');
    body.append(h('div', { class: 'row', style: { marginBottom: '10px' } }, ui.sevTag(r.severity), h('span', { class: 'tag' }, r.source_platform), h('span', { class: 'tag ' + (r.enabled_status === 'enabled' ? 'green' : 'grey') }, r.enabled_status), h('span', { class: 'tag' }, 'Quality ' + q.grade + ' (' + q.score + ')')));
    if (r.description) body.append(h('p', { class: 'small' }, r.description));
    const kv = h('dl', { class: 'kv' });
    const add = (k, v) => kv.append(h('dt', k), h('dd', v));
    add('Rule ID', h('span', { class: 'mono' }, r.rule_id));
    add('Source', r.source_platform + ' / ' + r.source_instance + ' (' + r.source_format + ')');
    add('ATT&CK', r.attack_techniques.length ? h('div', { class: 'row', style: { gap: '4px' } }, r.attack_techniques.map(t => h('span', { class: 'tag cyan' + (r.inferred_techniques.includes(t) ? ' inferred' : ''), title: r.inferred_techniques.includes(t) ? 'Inferred mapping' : 'Explicit mapping' }, ui.techLink(t)))) : 'Unmapped');
    add('Mapping source', r.mapping_source + (r.inferred_techniques.length ? ' — dashed tags are inferred, not confirmed' : ''));
    if (r.attack_tactics.length) add('Tactics', r.attack_tactics.map(t => SM.FW.tacticName(t)).join(', '));
    add('Log source types', r.log_source_types.join(', ') || '—');
    if (r.event_ids.length) add('Event IDs', r.event_ids.join(', '));
    if (r.event_fields.length) add('Fields', h('span', { class: 'xs mono' }, r.event_fields.join(', ')));
    if (r.threshold) add('Threshold', r.threshold.operator + ' ' + r.threshold.value);
    if (r.time_window) add('Time window', r.time_window.text || (r.time_window.value + ' ' + r.time_window.unit));
    if (r.grouping_fields.length) add('Group by', r.grouping_fields.join(', '));
    if (r.entity_context.length) add('Entities', r.entity_context.join(', '));
    if (r.d3fend_mapping.length) add('D3FEND', r.d3fend_mapping.join(', '));
    if (r.capec_mapping.length) add('CAPEC', r.capec_mapping.join(', '));
    add('Lifecycle', r.lifecycle_stage); add('Validation', r.validation_status);
    if (r.false_positive_notes) add('FP notes', r.false_positive_notes);
    if (r.owner) add('Owner', r.owner); if (r.last_modified) add('Modified', SM.fmtDate(r.last_modified));
    body.append(kv);
    // quality breakdown
    body.append(h('h3', { style: { marginTop: '14px' } }, 'Quality assessment'));
    body.append(SM.chartHBar(Object.entries(q.components).map(([k, v]) => ({ label: k, value: v })), { max: 100, unit: '/100' }));
    if (q.notes.length) body.append(h('ul', { class: 'small' }, q.notes.map(n => h('li', n))));
    body.append(h('h3', { style: { marginTop: '14px' } }, 'Detection logic'), h('pre', r.detection_logic || '(none)'));
    body.append(h('h3', { style: { marginTop: '14px' } }, 'Original imported rule'), h('pre', SM.truncate(typeof r.original_rule_content === 'string' ? r.original_rule_content : JSON.stringify(r.original_rule_content, null, 2), 4000)));
    const foot = h('div', { class: 'row', style: { marginTop: '12px' } }, h('button', { class: 'btn sm', onClick: () => { SM.download(SM.slug(r.rule_name || r.rule_id) + '.json', JSON.stringify(r, null, 2), 'application/json'); } }, 'Export rule JSON'), h('button', { class: 'btn sm', onClick: () => SM.App.go('validation', { rule: r.rule_id }) }, 'Validate'), h('button', { class: 'btn sm danger', onClick: async () => { if (await SM.confirm('Delete rule', 'Remove ' + r.rule_name + '?', { danger: true, okLabel: 'Delete' })) { await SM.Store.deleteRule(r.rule_id); SM.drawer.close(); SM.App.go('inventory'); } } }, 'Delete'));
    body.append(foot);
    SM.drawer.open(r.rule_name || r.rule_id, body, 'Normalised rule · fingerprint ' + r.fingerprint);
  }

  // ---- Import workflow ----
  const STEPS = ['Source', 'Platform', 'Upload', 'Parse', 'Normalise', 'Map ATT&CK', 'Duplicates', 'Summary', 'Approve'];
  function importView() {
    const wrap = h('div');
    const platform = h('select', null, h('option', { value: 'auto' }, 'Auto-detect'), SM.Import.PLATFORMS.map(p => h('option', { value: p }, ({ qradar: 'IBM QRadar', splunk: 'Splunk ES', elastic: 'Elastic Security', sentinel: 'Microsoft Sentinel', sigma: 'Sigma', generic: 'Generic / custom' }[p] || p))));
    const instance = h('input', { type: 'text', value: 'default', placeholder: 'SIEM instance label' });
    wrap.append(ui.card('1–2 · Source & platform', h('div', { class: 'form-grid' }, h('div', { class: 'field' }, h('label', 'Target SIEM platform'), platform), h('div', { class: 'field' }, h('label', 'SIEM instance'), instance))));
    const steps = h('div', { class: 'steps' }, STEPS.map((s, i) => h('span', { class: 'step', dataset: { i } }, (i + 1) + '. ' + s)));
    const drop = h('div', { class: 'dropzone' }, h('div', null, h('strong', 'Drop rule files here'), ' or click to browse'), h('div', { class: 'small muted', style: { marginTop: '6px' } }, 'JSON · NDJSON · CSV · Sigma YAML · QRadar XML · savedsearches.conf · ARM templates'));
    const fileInput = h('input', { type: 'file', multiple: true, accept: '.json,.ndjson,.csv,.tsv,.yml,.yaml,.xml,.conf,.txt', style: { display: 'none' } });
    drop.addEventListener('click', () => fileInput.click());
    drop.addEventListener('dragover', e => { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', e => { e.preventDefault(); drop.classList.remove('over'); handleFiles(e.dataTransfer.files); });
    fileInput.addEventListener('change', () => handleFiles(fileInput.files));
    wrap.append(ui.card('3 · Upload', h('div', null, drop, fileInput)));
    const out = h('div', { id: 'import-out' }); wrap.append(out);

    async function handleFiles(fileList) {
      const files = Array.from(fileList); if (!files.length) return;
      const prog = h('div', { class: 'progress', style: { marginBottom: '10px' } }, h('div', { style: { width: '0%' } }));
      SM.clear(out).append(ui.card('Processing', h('div', null, prog, h('div', { id: 'import-log', class: 'small muted' }, 'Parsing ' + files.length + ' file(s)…'))));
      markStep(3);
      const results = []; let allRules = [];
      for (let i = 0; i < files.length; i++) { const r = await SM.Import.parseFile(files[i], { platform: platform.value, instance: instance.value }); results.push(r); allRules = allRules.concat(r.rules); SM.$('#import-log').textContent = 'Parsed ' + r.filename + ': ' + r.rules.length + ' rules, ' + r.errors.length + ' errors'; prog.firstChild.style.width = Math.round(100 * (i + 1) / files.length) + '%'; await new Promise(r => setTimeout(r, 0)); }
      markStep(4); markStep(5);
      const quality = SM.Import.analyseBatch(allRules, SM.Store.rules);
      markStep(6); markStep(7);
      pendingImport = { files, results, rules: allRules, quality, platform: platform.value, instance: instance.value };
      renderSummary(out); markStep(8);
    }
    function markStep(n) { SM.$$('.step', steps).forEach((s, i) => { s.classList.toggle('done', i < n); s.classList.toggle('active', i === n); }); }
    wrap.insertBefore(steps, out);
    return wrap;
  }

  function renderSummary(out) {
    const { results, rules, quality } = pendingImport;
    SM.clear(out);
    const parsed = rules.length; const errs = SM.sum(results, r => r.errors.length);
    out.append(ui.card('8 · Import summary', h('div', null,
      h('div', { class: 'grid kpi' },
        ui.kpi('Parsed rules', SM.fmtNum(parsed), { color: 'green' }),
        ui.kpi('Parse errors', SM.fmtNum(errs), { color: errs ? 'red' : undefined }),
        ui.kpi('Duplicates (logic)', SM.fmtNum(quality.duplicates), { color: quality.duplicates ? 'amber' : undefined }),
        ui.kpi('Replacing existing', SM.fmtNum(quality.replacing_existing), { color: quality.replacing_existing ? 'amber' : undefined }),
        ui.kpi('Unmapped', SM.fmtNum(quality.missing_mapping), { color: quality.missing_mapping ? 'amber' : undefined }),
        ui.kpi('Inferred mapping only', SM.fmtNum(quality.inferred_only), { color: quality.inferred_only ? 'amber' : undefined }),
        ui.kpi('Missing description', SM.fmtNum(quality.missing_description)),
        ui.kpi('Malformed logic', SM.fmtNum(quality.malformed_logic), { color: quality.malformed_logic ? 'red' : undefined }),
        ui.kpi('Unknown log source', SM.fmtNum(quality.unknown_log_source))
      ))));
    // per-file adapters
    out.append(ui.card('Format adapters & detection', h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'File'), h('th', 'Format'), h('th', 'Adapter'), h('th', 'Rules'), h('th', 'Errors'))), h('tbody', results.map(r => h('tr', h('td', SM.truncate(r.filename, 36)), h('td', h('span', { class: 'tag' }, r.format)), h('td', h('span', { class: 'tag cyan' }, r.adapter)), h('td', SM.fmtNum(r.rules.length)), h('td', r.errors.length ? h('span', { class: 'tag red' }, r.errors.length) : '0')))))));
    if (quality.unsupported_field_names.length) out.append(ui.card('Unrecognised field names (top 25)', h('div', { class: 'row', style: { gap: '4px' } }, quality.unsupported_field_names.map(f => h('span', { class: 'tag amber', title: f.count + ' rules' }, f.field + ' ×' + f.count))), 'May need mapping to canonical fields'));
    const errList = results.flatMap(r => r.errors.map(e => Object.assign({ file: r.filename }, e)));
    if (errList.length) out.append(ui.card('Error report (' + errList.length + ')', h('div', { style: { maxHeight: '200px', overflow: 'auto' } }, h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'File'), h('th', 'Error'), h('th', 'Detail'))), h('tbody', errList.slice(0, 200).map(e => h('tr', h('td', SM.truncate(e.file, 24)), h('td', e.error), h('td', h('span', { class: 'xs mono' }, SM.truncate(e.raw || e.line || '', 60))))))))));
    out.append(h('div', { class: 'row', style: { marginTop: '14px' } },
      h('button', { class: 'btn primary', onClick: approveImport }, '9 · Approve & store ' + SM.fmtNum(parsed) + ' rules'),
      h('button', { class: 'btn ghost', onClick: () => { pendingImport = null; SM.App.go('inventory', { tab: 'import' }); } }, 'Discard'),
      quality.duplicates ? h('label', { class: 'check' }, h('input', { type: 'checkbox', id: 'skip-dupes', checked: true }), 'Skip ' + quality.duplicates + ' in-batch duplicates') : null
    ));
  }
  async function approveImport() {
    if (!pendingImport) return;
    const skip = SM.$('#skip-dupes') && SM.$('#skip-dupes').checked;
    let rules = pendingImport.rules; if (skip) rules = rules.filter(r => !r.duplicate_of);
    const batchId = SM.uid('batch');
    await SM.DB.put('import_batches', { batch_id: batchId, created_at: SM.now(), count: rules.length, files: pendingImport.files.map(f => f.name), platform: pendingImport.platform, quality: pendingImport.quality });
    await SM.Store.addRules(rules, batchId);
    SM.toast('Imported ' + rules.length + ' rules. Run a coverage assessment next.', 'ok');
    pendingImport = null;
    SM.App.go('inventory');
  }
  function batchesView() {
    const wrap = h('div');
    SM.DB.getAll('import_batches').then(batches => {
      if (!batches.length) { SM.clear(wrap).append(ui.empty('No imports yet', 'Import batches will be listed here with their quality reports.')); return; }
      SM.clear(wrap).append(h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'When'), h('th', 'Files'), h('th', 'Platform'), h('th', 'Rules'), h('th', 'Duplicates'), h('th', 'Unmapped'), h('th', ''))), h('tbody', batches.sort((a, b) => b.created_at.localeCompare(a.created_at)).map(b => h('tr', h('td', SM.fmtDate(b.created_at)), h('td', SM.truncate((b.files || []).join(', '), 40)), h('td', b.platform || '—'), h('td', SM.fmtNum(b.count)), h('td', (b.quality && b.quality.duplicates) || 0), h('td', (b.quality && b.quality.missing_mapping) || 0), h('td', h('button', { class: 'btn sm danger', onClick: async () => { if (await SM.confirm('Delete batch', 'Remove the ' + b.count + ' rules from this batch?', { danger: true, okLabel: 'Delete' })) { const del = SM.Store.rules.filter(r => r.import_batch === b.batch_id); for (const r of del) await SM.DB.delete('rules', r.rule_id); SM.Store.rules = SM.Store.rules.filter(r => r.import_batch !== b.batch_id); await SM.DB.delete('import_batches', b.batch_id); SM.emit('rules:changed'); SM.App.go('inventory', { tab: 2 }); } } }, 'Delete')))))));
    });
    return wrap;
  }

  function exportInventory() { if (!SM.Store.rules.length) return SM.toast('No rules to export', 'warn'); exportRows(SM.Store.rules); }
  function exportRows(rows) {
    const doExport = (f) => {
      if (f === 'JSON') SM.download('rule-inventory.json', JSON.stringify(rows, null, 1), 'application/json');
      else { const flat = rows.map(r => ({ rule_id: r.rule_id, rule_name: r.rule_name, platform: r.source_platform, enabled: r.enabled_status, severity: r.severity, risk_score: r.risk_score, techniques: r.attack_techniques.join('|'), mapping_source: r.mapping_source, log_source_types: r.log_source_types.join('|'), event_ids: r.event_ids.join('|'), lifecycle: r.lifecycle_stage, validation: r.validation_status, quality_flags: r.quality_flags.join('|') })); SM.download('rule-inventory.csv', SM.toCSV(flat), 'text/csv'); }
      SM.$('#modal-back').classList.remove('open');
    };
    const btns = ['JSON', 'CSV'].map(f => h('button', { class: 'btn', onClick: () => doExport(f) }, f));
    SM.modal({ title: 'Export ' + SM.fmtNum(rows.length) + ' rules', body: h('div', { class: 'row' }, btns) });
  }
  function saveCurrentFilter() { SM.prompt('Save filter', 'Filter name').then(name => { if (name) SM.Store.saveFilter({ name, query: SM.$('#global-search') ? '' : '', state: {} }).then(() => SM.App.go('inventory')); }); }
  async function loadDemo() { await SM.Demo.load(); SM.App.go('inventory'); }
})(globalThis.SM = globalThis.SM || {});
