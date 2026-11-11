/* SENTINEL MATRIX — Offense & Alert Analytics + Log Source Intelligence. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;

  SM.registerModule('offenses', {
    title: 'Offense & Alert Analytics', subtitle: 'Operational effectiveness from offenses, alerts and rule trigger history',
    render(body, params, actions) {
      actions.append(h('button', { class: 'btn ghost', onClick: () => importData('offenses') }, '⬆ Import offenses'), h('button', { class: 'btn ghost', onClick: () => importData('alerts') }, '⬆ Import alerts'));
      const S = SM.Store;
      if (!S.offenses.length && !S.alerts.length) { body.append(ui.empty('No offense/alert data', 'Import offenses and alerts (JSON/CSV) or run a live/simulated SIEM audit to analyse operational effectiveness.', h('div', { class: 'row' }, h('button', { class: 'btn', onClick: () => importData('offenses') }, 'Import offenses'), h('button', { class: 'btn primary', onClick: () => SM.App.go('liveaudit') }, 'Run audit')))); return; }
      const open = S.offenses.filter(o => /open/i.test(o.status)); const closed = S.offenses.filter(o => /clos/i.test(o.status));
      const high = S.offenses.filter(o => SM.normSeverity(o.severity) === 'critical' || SM.normSeverity(o.severity) === 'high');
      const alertVol = SM.sum(S.alerts, a => a.count || 1);
      body.append(h('div', { class: 'grid kpi' },
        ui.kpi('Total offenses', SM.fmtNum(S.offenses.length)),
        ui.kpi('Open offenses', SM.fmtNum(open.length), { color: open.length ? 'orange' : undefined }),
        ui.kpi('Closed offenses', SM.fmtNum(closed.length)),
        ui.kpi('High-severity', SM.fmtNum(high.length), { color: high.length ? 'red' : undefined }),
        ui.kpi('Alert volume', SM.fmtNum(alertVol), { color: 'cyan' }),
        ui.kpi('Rules triggering', SM.fmtNum(SM.uniq(S.alerts.map(a => a.rule_id)).length))
      ));
      // offense analysis
      body.append(h('div', { class: 'grid c2', style: { margin: '14px 0' } },
        ui.card('Offenses by severity', SM.chartHBar(SM.SEVERITIES.map(s => ({ label: s, value: S.offenses.filter(o => SM.normSeverity(o.severity) === s).length, color: ({ critical: SM.CHART_COLORS.red, high: SM.CHART_COLORS.orange, medium: SM.CHART_COLORS.amber, low: SM.CHART_COLORS.cyan, informational: SM.CHART_COLORS.grey }[s]) })), { unit: 'offenses' })),
        ui.card('Offenses by network zone', SM.chartHBar(offensesByZone(), { unit: 'offenses', color: SM.CHART_COLORS.violet }))
      ));
      // effectiveness assessment
      const eff = effectivenessReport();
      body.append(ui.card('Rule effectiveness assessment', h('div', null,
        h('div', { class: 'small muted', style: { marginBottom: '8px' } }, 'A rule is not judged ineffective solely because it has not triggered — observation period, expected frequency, telemetry availability and purpose are all considered.'),
        h('div', { class: 'grid c2' },
          effCard('Enabled, never triggered', eff.neverTriggered, 'info', 'May be fine if the technique is rare and telemetry is present — review expected frequency.'),
          effCard('Triggering excessively', eff.excessive, 'high', 'High daily volume — candidates for tuning.'),
          effCard('Recurring offense sources', eff.offenseStorm, 'high', 'Most alerts become offenses.'),
          effCard('No supporting telemetry', eff.noTelemetry, 'high', 'Cannot fire regardless of activity.'),
          effCard('Depends on stale log source', eff.staleSource, 'medium', 'Underlying log source is inactive/stale.'),
          effCard('High false-positive ratio', eff.highFp, 'medium', 'Recurring false positives recorded.')
        )
      )));
      // offenses table
      if (S.offenses.length) { const table = SM.VTable([
        { key: 'id', label: 'ID', width: '0.7fr', render: o => h('span', { class: 'mono xs' }, SM.truncate(o.id, 12)) },
        { key: 'description', label: 'Offense', width: '2.2fr', render: o => SM.truncate(o.description || '—', 50) },
        { key: 'severity', label: 'Severity', width: '0.8fr', render: o => ui.sevTag(o.severity) },
        { key: 'magnitude', label: 'Magnitude', width: '0.8fr', align: 'right', render: o => o.magnitude || '—' },
        { key: 'status', label: 'Status', width: '0.8fr', render: o => h('span', { class: 'tag ' + (/open/i.test(o.status) ? 'orange' : 'grey') }, o.status) },
        { key: 'event_count', label: 'Events', width: '0.7fr', align: 'right', render: o => SM.fmtNum(o.event_count || 0) },
        { key: 'rule_ids', label: 'Rules', width: '1fr', render: o => h('span', { class: 'xs muted' }, (o.rule_ids || []).length + ' rule(s)') }
      ], { idKey: 'id', maxHeight: 420, sortKey: 'magnitude', sortDir: -1, onRow: openOffense });
        body.append(ui.card('Offenses', table.el)); table.setRows(S.offenses); }
    }
  });
  function effCard(label, rules, sev, note) { return h('div', { class: 'card', style: { padding: '12px', borderLeft: '3px solid var(--' + (sev === 'high' ? 'red' : sev === 'medium' ? 'amber' : 'cyan') + ')' } }, h('div', { class: 'row spread' }, h('strong', label), h('span', { class: 'tag ' + (rules.length ? (sev === 'high' ? 'red' : sev === 'medium' ? 'amber' : 'cyan') : 'green') }, rules.length)), h('div', { class: 'xs muted', style: { margin: '4px 0' } }, note), rules.length ? h('div', { class: 'small', style: { maxHeight: '90px', overflow: 'auto' } }, rules.slice(0, 8).map(r => h('div', h('a', { href: '#', onClick: e => { e.preventDefault(); SM.App.go('inventory', { focus: r.rule_id }); } }, SM.truncate(r.name, 44))))) : h('div', { class: 'xs muted' }, 'None')); }
  function effectivenessReport() {
    const S = SM.Store; const tel = S.telemetry(); const stats = S.alertStats(); const stale = S.staleLogSources();
    const out = { neverTriggered: [], excessive: [], offenseStorm: [], noTelemetry: [], staleSource: [], highFp: [] };
    for (const r of S.rules) { const e = SM.Quality.effectiveness(r, { alertStats: stats, telemetry: tel, staleLogSources: stale }); for (const f of e.flags) { const map = { never_triggered: 'neverTriggered', excessive: 'excessive', offense_storm: 'offenseStorm', no_telemetry: 'noTelemetry', stale_source: 'staleSource', high_fp: 'highFp' }; if (map[f.k]) out[map[f.k]].push({ rule_id: r.rule_id, name: r.rule_name || r.rule_id, text: f.text }); } }
    return out;
  }
  function offensesByZone() { const S = SM.Store; const assetZone = {}; for (const a of S.assets) { if (a.ip) assetZone[a.ip] = a.zone; if (a.hostname) assetZone[a.hostname.toLowerCase()] = a.zone; } const m = {}; for (const o of S.offenses) { const z = o.zone || assetZone[o.source_ip] || assetZone[(o.source_host || '').toLowerCase()] || 'Unknown'; m[z] = (m[z] || 0) + 1; } return Object.entries(m).map(([z, v]) => ({ label: z, value: v })).sort((a, b) => b.value - a.value); }
  function openOffense(o) { SM.drawer.open('Offense ' + o.id, h('div', null, h('dl', { class: 'kv' }, h('dt', 'Description'), h('dd', o.description || '—'), h('dt', 'Severity'), h('dd', ui.sevTag(o.severity)), h('dt', 'Magnitude'), h('dd', o.magnitude || '—'), h('dt', 'Status'), h('dd', o.status), h('dt', 'Events'), h('dd', SM.fmtNum(o.event_count || 0)), h('dt', 'Source'), h('dd', o.source_ip || o.source_host || '—'), h('dt', 'Category'), h('dd', o.category || '—'), h('dt', 'First seen'), h('dd', SM.fmtDate(o.first_seen)), h('dt', 'Last seen'), h('dd', SM.fmtDate(o.last_seen))), h('h3', { style: { marginTop: '12px' } }, 'Associated rules'), h('div', null, (o.rule_ids || []).length ? (o.rule_ids || []).map(id => { const r = SM.Store.rules.find(x => x.rule_id === id); return h('div', { class: 'small' }, h('a', { href: '#', onClick: e => { e.preventDefault(); SM.App.go('inventory', { focus: id }); } }, r ? r.rule_name : id)); }) : h('span', { class: 'muted small' }, 'None linked')))); }

  // ---------------- Log Source Intelligence ----------------
  SM.registerModule('logsources', {
    title: 'Log Source Intelligence', subtitle: 'Telemetry inventory, health, and detection contribution',
    render(body, params, actions) {
      actions.append(h('button', { class: 'btn ghost', onClick: () => importData('log_sources') }, '⬆ Import log sources'), h('button', { class: 'btn ghost', onClick: addLogSource }, '＋ Add source'), h('button', { class: 'btn ghost', onClick: telemetryPlan }, 'Onboarding plan'));
      const S = SM.Store;
      if (!S.logSources.length) { body.append(ui.empty('No log sources', 'Import a log source inventory or add sources manually. Telemetry health directly affects coverage confidence.', h('div', { class: 'row' }, h('button', { class: 'btn', onClick: () => importData('log_sources') }, 'Import'), h('button', { class: 'btn ghost', onClick: seedFromProfile }, 'Seed from active profile')))); return; }
      const healthy = S.logSources.filter(l => l.health_status === 'healthy'); const stale = S.logSources.filter(l => l.health_status === 'stale'); const inactive = S.logSources.filter(l => l.health_status === 'inactive' || l.collection_status === 'inactive');
      body.append(h('div', { class: 'grid kpi' },
        ui.kpi('Log sources', SM.fmtNum(S.logSources.length), { color: 'cyan' }),
        ui.kpi('Healthy', SM.fmtNum(healthy.length), { color: 'green' }),
        ui.kpi('Stale', SM.fmtNum(stale.length), { color: stale.length ? 'amber' : undefined }),
        ui.kpi('Inactive', SM.fmtNum(inactive.length), { color: inactive.length ? 'red' : undefined }),
        ui.kpi('Source types', SM.uniq(S.logSources.map(l => l.source_type)).length),
        ui.kpi('Zones covered', SM.uniq(S.logSources.map(l => l.zone)).filter(Boolean).length)
      ));
      body.append(h('div', { class: 'grid c2', style: { margin: '14px 0' } },
        ui.card('Health distribution', SM.chartDonut(['healthy', 'stale', 'inactive', 'unknown'].map(s => ({ label: s, value: S.logSources.filter(l => (l.health_status || 'unknown') === s).length, color: { healthy: SM.CHART_COLORS.green, stale: SM.CHART_COLORS.amber, inactive: SM.CHART_COLORS.red, unknown: SM.CHART_COLORS.grey }[s] })), { centerLabel: { big: SM.pct(healthy.length, S.logSources.length) + '%', small: 'healthy' } })),
        ui.card('Telemetry gaps vs required', telemetryGapChart())
      ));
      const table = SM.VTable([
        { key: 'source_name', label: 'Source', width: '2fr', render: l => h('div', null, h('div', l.source_name || l.id), h('div', { class: 'xs muted' }, l.hostname || '')) },
        { key: 'source_type', label: 'Type', width: '1.4fr', render: l => h('span', { class: 'tag' }, SM.FW.logSourceType(l.source_type).name) },
        { key: 'zone', label: 'Zone', width: '1.2fr', render: l => l.zone || '—' },
        { key: 'health_status', label: 'Health', width: '0.9fr', render: l => h('span', { class: 'tag ' + ({ healthy: 'green', stale: 'amber', inactive: 'red' }[l.health_status] || 'grey') }, l.health_status || 'unknown') },
        { key: 'last_event', label: 'Last event', width: '1.2fr', render: l => h('span', { class: 'xs' }, SM.fmtDate(l.last_event)) },
        { key: 'event_volume', label: 'Volume/day', width: '0.9fr', align: 'right', render: l => SM.fmtNum(l.event_volume || 0) },
        { key: 'coverage', label: 'Techniques', width: '0.9fr', align: 'right', render: l => SM.fmtNum(techniquesForSourceType(l.source_type)) }
      ], { idKey: 'id', maxHeight: 460, sortKey: 'source_name', onRow: openLogSource });
      body.append(table.el); table.setRows(S.logSources);
    }
  });
  function techniquesForSourceType(type) { let n = 0; for (const t of SM.FW.allTechniques()) if (SM.FW.telemetryFor(t.id).logSourceTypes.includes(type)) n++; return n; }
  function telemetryGapChart() { const S = SM.Store; const tel = S.telemetry(); const required = {}; for (const t of SM.FW.allTechniques()) for (const x of SM.FW.telemetryFor(t.id).logSourceTypes) required[x] = (required[x] || 0) + 1; const data = Object.entries(required).sort((a, b) => b[1] - a[1]).slice(0, 10).map(([type, cnt]) => ({ label: SM.FW.logSourceType(type).name, value: cnt, color: tel.available.has(type) ? SM.CHART_COLORS.green : SM.CHART_COLORS.red })); return h('div', null, SM.chartHBar(data, { unit: 'techniques need it' }), SM.legend([{ label: 'Present', color: SM.CHART_COLORS.green }, { label: 'Missing', color: SM.CHART_COLORS.red }])); }
  function openLogSource(l) { const types = SM.FW.telemetryFor; const linked = SM.Store.rules.filter(r => r.log_source_types.includes(l.source_type)); SM.drawer.open(l.source_name || l.id, h('div', null, h('dl', { class: 'kv' }, h('dt', 'Type'), h('dd', SM.FW.logSourceType(l.source_type).name), h('dt', 'Hostname'), h('dd', l.hostname || '—'), h('dt', 'IP'), h('dd', l.ip || '—'), h('dt', 'Zone'), h('dd', l.zone || '—'), h('dt', 'Platform'), h('dd', l.platform || SM.FW.logSourceType(l.source_type).platform), h('dt', 'Collection'), h('dd', l.collection_status || '—'), h('dt', 'Health'), h('dd', h('span', { class: 'tag ' + ({ healthy: 'green', stale: 'amber', inactive: 'red' }[l.health_status] || 'grey') }, l.health_status || 'unknown')), h('dt', 'Last event'), h('dd', SM.fmtDate(l.last_event)), h('dt', 'Volume/day'), h('dd', SM.fmtNum(l.event_volume || 0)), h('dt', 'Required event IDs'), h('dd', (l.required_event_ids || []).join(', ') || '—'), h('dt', 'Missing event IDs'), h('dd', (l.missing_event_ids || []).length ? h('span', { style: { color: 'var(--red)' } }, l.missing_event_ids.join(', ')) : 'None')), h('h3', { style: { marginTop: '12px' } }, 'Detection contribution'), h('div', { class: 'small' }, 'This source type supports ' + techniquesForSourceType(l.source_type) + ' ATT&CK techniques and ' + linked.length + ' imported rules.'), h('div', { class: 'row', style: { marginTop: '10px' } }, h('button', { class: 'btn sm', onClick: () => editLogSource(l) }, 'Edit'), h('button', { class: 'btn sm danger', onClick: async () => { await SM.DB.delete('log_sources', l.id); SM.Store.logSources = SM.Store.logSources.filter(x => x.id !== l.id); SM.emit('logsources:changed'); SM.drawer.close(); SM.App.go('logsources'); } }, 'Delete')))); }
  function addLogSource() { editLogSource({ id: SM.uid('ls'), source_name: '', source_type: 'windows_security', zone: '', health_status: 'healthy', collection_status: 'active', event_volume: 0, last_event: SM.now() }); }
  function editLogSource(l) { const f = Object.assign({}, l); const fld = (label, key, opts, type = 'text') => h('div', { class: 'field' }, h('label', label), opts ? h('select', { onChange: e => f[key] = e.target.value }, opts.map(o => h('option', { value: o.v, selected: f[key] === o.v }, o.l))) : h('input', { type, value: f[key] || '', onInput: e => f[key] = type === 'number' ? Number(e.target.value) : e.target.value })); SM.modal({ title: l.source_name ? 'Edit log source' : 'Add log source', body: h('div', { class: 'form-grid' }, fld('Name', 'source_name'), fld('Type', 'source_type', (SM.FW.logSourceCatalog.types || []).map(t => ({ v: t.id, l: t.name }))), fld('Hostname', 'hostname'), fld('IP', 'ip'), fld('Zone', 'zone', SM.FW.logSourceCatalog.zones.map(z => ({ v: z, l: z }))), fld('Health', 'health_status', ['healthy', 'stale', 'inactive', 'unknown'].map(v => ({ v, l: v }))), fld('Collection', 'collection_status', ['active', 'inactive'].map(v => ({ v, l: v }))), fld('Volume/day', 'event_volume', null, 'number')), footer: close => [h('button', { class: 'btn', onClick: close }, 'Cancel'), h('button', { class: 'btn primary', onClick: async () => { await SM.Store.upsertLogSources([f]); close(); SM.drawer.close(); SM.App.go('logsources'); } }, 'Save')] }); }
  function seedFromProfile() { const p = SM.Store.profile(); if (!p) return; const sources = (p.expected_log_sources || []).map(t => ({ id: 'ls_' + t, source_name: SM.FW.logSourceType(t).name, source_type: t, zone: (p.zones || [])[0] || '', platform: SM.FW.logSourceType(t).platform, health_status: 'healthy', collection_status: 'active', last_event: SM.now(), event_volume: 10000, required_event_ids: (p.expected_event_ids || {})[t] || [] })); SM.Store.upsertLogSources(sources).then(() => SM.App.go('logsources')); SM.toast('Seeded ' + sources.length + ' expected log sources from profile', 'ok'); }
  function telemetryPlan() { const S = SM.Store; const tel = S.telemetry(); const required = {}; for (const t of SM.FW.allTechniques()) for (const x of SM.FW.telemetryFor(t.id).logSourceTypes) { required[x] = required[x] || { techniques: 0, present: tel.available.has(x) }; required[x].techniques++; } const missing = Object.entries(required).filter(([, v]) => !v.present).sort((a, b) => b[1].techniques - a[1].techniques); SM.drawer.open('Telemetry onboarding plan', h('div', null, missing.length ? h('div', null, h('p', { class: 'small muted' }, 'Onboarding these missing log source types would unlock detection for the most techniques. Prioritised by technique count:'), h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'Log source'), h('th', 'Techniques unlocked'), h('th', 'Platform'))), h('tbody', missing.slice(0, 20).map(([type, v]) => h('tr', h('td', SM.FW.logSourceType(type).name), h('td', h('strong', v.techniques)), h('td', SM.FW.logSourceType(type).platform)))))) : h('div', { class: 'empty' }, 'All required log source types are present.'))); }

  function importData(store) { const inp = h('input', { type: 'file', accept: '.json,.csv', style: { display: 'none' }, onChange: async e => { const f = e.target.files[0]; if (!f) return; try { const text = await SM.readFileText(f); const fmt = SM.detectFormat(f.name, text); let rows = fmt === 'csv' ? SM.parseCSV(text).records : SM.safeJSON(text); rows = Array.isArray(rows) ? rows : (rows[store] || rows.items || [rows]); if (store === 'log_sources') { await SM.Store.upsertLogSources(rows.map(SM.Demo.normLogSource)); } else if (store === 'offenses') { await SM.Store.upsertOffenses(rows.map(SM.Demo.normOffense)); } else if (store === 'alerts') { await SM.Store.upsertAlerts(rows.map((a, i) => ({ id: a.id || SM.uid('alert'), rule_id: a.rule_id || a.rule || a.ruleId || '', count: Number(a.count || 1), severity: a.severity, false_positive: !!a.false_positive, at: a.at || a.timestamp }))); } SM.toast('Imported ' + rows.length + ' records', 'ok'); SM.App.go(store === 'log_sources' ? 'logsources' : 'offenses'); } catch (err) { SM.toast('Import failed: ' + err.message, 'err'); } } }); document.body.appendChild(inp); inp.click(); setTimeout(() => inp.remove(), 1000); }
})(globalThis.SM = globalThis.SM || {});
