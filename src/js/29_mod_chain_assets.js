/* SENTINEL MATRIX — Attack Chain Analysis + Enterprise Asset Context. */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;
  // Example multi-stage chain + bundled scenario chains
  const CHAINS = {
    default: { name: 'Full intrusion chain', tactics: ['TA0001', 'TA0002', 'TA0003', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0010'] },
    ransomware: { name: 'Ransomware operation', tactics: ['TA0001', 'TA0002', 'TA0003', 'TA0006', 'TA0008', 'TA0005', 'TA0040'] },
    ad_compromise: { name: 'Active Directory compromise', tactics: ['TA0001', 'TA0006', 'TA0004', 'TA0007', 'TA0008', 'TA0003'] },
    exfiltration: { name: 'Data theft', tactics: ['TA0001', 'TA0007', 'TA0008', 'TA0009', 'TA0011', 'TA0010'] }
  };

  SM.registerModule('chain', {
    title: 'Attack Chain Analysis', subtitle: 'Detection coverage across multi-stage adversary behaviour',
    render(body, params, actions) {
      const cov = SM.Store.coverage;
      if (!cov) { body.append(ui.empty('No coverage assessment', 'Run a coverage assessment to analyse attack chain detection.', h('button', { class: 'btn primary', onClick: () => SM.runCoverage().then(() => SM.App.go('chain')) }, 'Run assessment'))); return; }
      const sel = h('select', { onChange: () => render() }, Object.entries(CHAINS).map(([k, c]) => h('option', { value: k }, c.name)));
      actions.append(h('div', { class: 'field', style: { minWidth: '220px' } }, sel));
      const wrap = h('div', { id: 'chain-wrap' }); body.append(wrap);
      function render() {
        const chain = CHAINS[sel.value]; const w = SM.clear(wrap);
        const covMap = new Map(cov.results.map(r => [r.technique_id, r]));
        const stages = chain.tactics.map(tid => { const techs = SM.FW.techniquesForTactic(tid, { parentsOnly: true }); const applicable = techs.map(t => covMap.get(t.id)).filter(r => r && r.classification !== 'NOT_APPLICABLE'); const covered = applicable.filter(r => ['VALIDATED', 'FULLY_COVERED'].includes(r.classification)).length; const partial = applicable.filter(r => r.classification === 'PARTIALLY_COVERED').length; const pct = applicable.length ? Math.round(100 * (covered + partial * 0.5) / applicable.length) : 0; return { tid, name: SM.FW.tacticName(tid), techs, applicable, covered, partial, pct, rules: SM.uniq(applicable.flatMap(r => r.rule_ids)).length }; });
        // chain viz
        const viz = h('div', { class: 'chain' });
        stages.forEach((s, i) => { const col = s.pct >= 60 ? SM.CHART_COLORS.green : s.pct >= 30 ? SM.CHART_COLORS.amber : SM.CHART_COLORS.red; const stage = h('div', { class: 'chain-stage', onClick: () => openStage(s), style: { borderColor: col } }, h('div', { class: 'st' }, 'Stage ' + (i + 1)), h('div', { style: { fontSize: '12px', fontWeight: 600 } }, s.name), h('div', { class: 'big', style: { color: col } }, s.pct + '%'), h('div', { class: 'xs muted' }, s.covered + '/' + s.applicable.length + ' covered · ' + s.rules + ' rules'), h('div', { class: 'bar' }, h('div', { style: { width: s.pct + '%', background: col } }))); viz.append(stage); });
        w.append(ui.card(chain.name + ' — chain coverage', viz, 'click a stage for detail'));
        // transition gaps
        const weak = stages.filter(s => s.pct < 40);
        w.append(h('div', { class: 'grid c2', style: { marginTop: '14px' } },
          ui.card('Chain coverage profile', SM.chartLine([{ label: 'Coverage %', points: stages.map(s => s.pct), color: SM.CHART_COLORS.cyan }], { labels: stages.map(s => SM.FW.tacticShort(s.tid)), height: 200, unit: '%' })),
          ui.card('Weakest stages & transition gaps', weak.length ? h('div', null, h('p', { class: 'small muted' }, 'An adversary is most likely to evade detection at these stages. Breaking the chain at any strong stage disrupts the operation.'), weak.map(s => h('div', { class: 'row spread', style: { padding: '4px 0' } }, h('span', null, h('span', { class: 'tag red' }, s.pct + '%'), ' ' + s.name), h('button', { class: 'btn sm', onClick: () => openStage(s) }, 'Remediate')))) : h('div', { class: 'small muted' }, 'No critically weak stages in this chain.'))
        ));
        // correlation recommendation
        w.append(ui.card('Recommended correlation rules', h('ul', { class: 'small' }, chainCorrelations(chain, stages).map(c => h('li', c)))));
      }
      function openStage(s) { const covMap = new Map(cov.results.map(r => [r.technique_id, r])); SM.drawer.open(s.name + ' — stage detection', h('div', null, h('div', { class: 'row', style: { marginBottom: '8px' } }, h('span', { class: 'tag' }, s.pct + '% covered'), h('span', { class: 'tag' }, s.applicable.length + ' techniques'), h('span', { class: 'tag' }, s.rules + ' rules')), h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'Technique'), h('th', 'Coverage'), h('th', 'Rules'))), h('tbody', s.applicable.sort((a, b) => SM.COVERAGE[a.classification].rank - SM.COVERAGE[b.classification].rank).map(r => h('tr', h('td', h('a', { href: '#', onClick: e => { e.preventDefault(); SM.matrixPanel(r.technique_id); } }, r.technique_id + ' ' + SM.truncate(r.technique_name, 24))), h('td', ui.covTag(r.classification)), h('td', r.rule_ids.length))))))); }
      render();
    }
  });
  function chainCorrelations(chain, stages) { const out = []; for (let i = 0; i < stages.length - 1; i++) { if (stages[i].pct > 30 && stages[i + 1].pct > 30) out.push('Correlate ' + stages[i].name + ' → ' + stages[i + 1].name + ' on the same host/user within 1 hour to raise a high-confidence multi-stage offense.'); } if (!out.length) out.push('Strengthen individual stage coverage before building cross-stage correlation.'); out.push('Use a risk-based scoring rule that accumulates across stages per entity (user/host) and alerts when cumulative risk crosses a threshold.'); return out; }

  // ---------------- Enterprise Asset Context ----------------
  SM.registerModule('assets', {
    title: 'Enterprise Asset Context', subtitle: 'Assets, zones, criticality and per-zone detection coverage',
    render(body, params, actions) {
      actions.append(h('button', { class: 'btn ghost', onClick: importAssets }, '⬆ Import assets (CMDB/AD/SCCM/EDR/IPAM)'), h('button', { class: 'btn ghost', onClick: manageZones }, 'Zones'));
      const S = SM.Store;
      if (!S.assets.length) { body.append(ui.empty('No assets loaded', 'Import a CMDB / Active Directory / SCCM / EDR / IPAM export to assess coverage by asset and zone.', h('button', { class: 'btn', onClick: importAssets }, 'Import assets'))); return; }
      const crit = S.assets.filter(a => /crit|high/i.test(a.criticality));
      body.append(h('div', { class: 'grid kpi' },
        ui.kpi('Total assets', SM.fmtNum(S.assets.length), { color: 'cyan' }),
        ui.kpi('Critical assets', SM.fmtNum(crit.length), { color: crit.length ? 'red' : undefined }),
        ui.kpi('Zones', SM.uniq(S.assets.map(a => a.zone)).filter(Boolean).length),
        ui.kpi('Business units', SM.uniq(S.assets.map(a => a.business_unit)).filter(Boolean).length),
        ui.kpi('Platforms', SM.uniq(S.assets.map(a => SM.Coverage.assetPlatform(a.os))).length)
      ));
      body.append(h('div', { class: 'grid c2', style: { margin: '14px 0' } },
        ui.card('Assets by zone', SM.chartHBar(byField('zone'), { unit: 'assets', color: SM.CHART_COLORS.violet })),
        ui.card('Per-zone telemetry coverage', zoneTelemetry())
      ));
      body.append(ui.card('Platform-specific coverage differences', platformCoverage(), 'e.g. a technique covered on Windows endpoints but not on Domain Controllers'));
      const table = SM.VTable([
        { key: 'hostname', label: 'Host', width: '1.6fr', render: a => h('div', null, h('div', a.hostname || a.asset_id), h('div', { class: 'xs muted' }, a.ip || '')) },
        { key: 'os', label: 'OS / platform', width: '1.4fr', render: a => h('span', null, SM.truncate(a.os || '—', 22), ' ', h('span', { class: 'tag' }, SM.Coverage.assetPlatform(a.os))) },
        { key: 'zone', label: 'Zone', width: '1.3fr' },
        { key: 'business_unit', label: 'BU', width: '1fr', render: a => a.business_unit || '—' },
        { key: 'criticality', label: 'Criticality', width: '0.9fr', render: a => h('span', { class: 'tag ' + (/crit/i.test(a.criticality) ? 'red' : /high/i.test(a.criticality) ? 'orange' : /med/i.test(a.criticality) ? 'amber' : 'grey') }, a.criticality || '—') },
        { key: 'log_sources', label: 'Log sources', width: '1fr', render: a => SM.fmtNum((a.log_sources || []).length) }
      ], { idKey: 'asset_id', maxHeight: 460, sortKey: 'criticality', onRow: openAsset });
      body.append(table.el); table.setRows(S.assets);
    }
  });
  function byField(f) { const m = SM.countBy(SM.Store.assets, a => a[f] || 'Unassigned'); return Object.entries(m).map(([k, v]) => ({ label: k, value: v })).sort((a, b) => b.value - a.value); }
  function zoneTelemetry() { const S = SM.Store; const tel = S.telemetry(); const zones = SM.uniq(S.assets.map(a => a.zone)).filter(Boolean); const data = zones.map(z => { const types = SM.uniq(S.logSources.filter(l => l.zone === z).map(l => l.source_type)); const expected = (S.profile() && S.profile().expected_log_sources) || []; return { label: z, value: expected.length ? Math.round(100 * types.filter(t => expected.includes(t)).length / expected.length) : types.length }; }); return SM.chartHBar(data, { max: 100, unit: '% expected sources', color: SM.CHART_COLORS.blue }); }
  function platformCoverage() { const S = SM.Store; const cov = S.coverage; if (!cov) return h('div', { class: 'small muted' }, 'Run a coverage assessment to see platform differences.'); const platforms = SM.uniq(S.assets.map(a => SM.Coverage.assetPlatform(a.os))).filter(p => p !== 'Unknown'); const rows = platforms.map(p => { const techs = cov.results.filter(r => { const t = SM.FW.technique(r.technique_id); return t && (t.platforms || []).includes(p) && r.classification !== 'NOT_APPLICABLE'; }); const covered = techs.filter(r => ['VALIDATED', 'FULLY_COVERED'].includes(r.classification)).length; return { label: p, value: techs.length ? Math.round(100 * covered / techs.length) : 0, count: techs.length }; }); return SM.chartHBar(rows.map(r => ({ label: r.label + ' (' + r.count + ')', value: r.value })), { max: 100, unit: '% covered', color: SM.CHART_COLORS.cyan }); }
  function openAsset(a) { const rules = SM.Store.rules.filter(r => r.log_source_types.some(t => (a.log_sources || []).includes(t))); SM.drawer.open(a.hostname || a.asset_id, h('div', null, h('dl', { class: 'kv' }, h('dt', 'Asset ID'), h('dd', a.asset_id), h('dt', 'Hostname'), h('dd', a.hostname || '—'), h('dt', 'IP'), h('dd', a.ip || '—'), h('dt', 'OS'), h('dd', a.os || '—'), h('dt', 'Platform'), h('dd', SM.Coverage.assetPlatform(a.os)), h('dt', 'Zone'), h('dd', a.zone || '—'), h('dt', 'Business unit'), h('dd', a.business_unit || '—'), h('dt', 'Criticality'), h('dd', a.criticality || '—'), h('dt', 'Data sensitivity'), h('dd', a.data_sensitivity || '—'), h('dt', 'Exposure'), h('dd', a.exposure || '—'), h('dt', 'Owner'), h('dd', a.owner || '—'), h('dt', 'Log sources'), h('dd', (a.log_sources || []).map(t => SM.FW.logSourceType(t).name).join(', ') || '—')), h('h3', { style: { marginTop: '12px' } }, 'Applicable detection rules'), h('div', { class: 'small' }, rules.length + ' rules reference this asset\'s log source types.'))); }
  function manageZones() { SM.drawer.open('Network zones', h('div', null, h('p', { class: 'small muted' }, 'Zones used for segmentation modelling and per-zone coverage:'), h('div', { class: 'row', style: { gap: '4px' } }, SM.FW.logSourceCatalog.zones.map(z => h('span', { class: 'tag violet' }, z))), h('p', { class: 'small muted', style: { marginTop: '12px' } }, 'Custom zones are supported — assets and log sources can use any zone value on import.'))); }
  function importAssets() { const inp = h('input', { type: 'file', accept: '.json,.csv', style: { display: 'none' }, onChange: async e => { const f = e.target.files[0]; if (!f) return; try { const text = await SM.readFileText(f); const fmt = SM.detectFormat(f.name, text); let rows = fmt === 'csv' ? SM.parseCSV(text).records : SM.safeJSON(text); rows = Array.isArray(rows) ? rows : (rows.assets || rows.items || [rows]); const norm = rows.map((a, i) => ({ asset_id: SM.str(a.asset_id || a.id || a.hostname || a.name || ('asset-' + i)), hostname: SM.str(a.hostname || a.name || a.host || a.ComputerName || ''), ip: SM.str(a.ip || a.ip_address || a.IPAddress || a.address || ''), os: SM.str(a.os || a.operating_system || a.OperatingSystem || a.platform || ''), business_unit: SM.str(a.business_unit || a.bu || a.department || a.OU || ''), zone: SM.str(a.zone || a.network_zone || a.vlan || a.segment || ''), asset_type: SM.str(a.asset_type || a.type || a.DeviceType || ''), criticality: SM.str(a.criticality || a.critical || a.importance || 'medium'), owner: SM.str(a.owner || ''), data_sensitivity: SM.str(a.data_sensitivity || a.sensitivity || ''), exposure: SM.str(a.exposure || ''), log_sources: SM.asArray(a.log_sources || a.logsources || []).map(SM.str) })); await SM.Store.upsertAssets(norm); SM.toast('Imported ' + norm.length + ' assets', 'ok'); SM.App.go('assets'); } catch (err) { SM.toast('Import failed: ' + err.message, 'err'); } } }); document.body.appendChild(inp); inp.click(); setTimeout(() => inp.remove(), 1000); }
})(globalThis.SM = globalThis.SM || {});
