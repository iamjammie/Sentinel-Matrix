/* SENTINEL MATRIX — SIEM Live Audit module (read-only, via local audit agent). */
(function (SM) {
  'use strict';
  const h = SM.h; const ui = SM.ui;
  const PLATFORMS = [['qradar', 'IBM QRadar'], ['splunk', 'Splunk Enterprise Security'], ['sentinel', 'Microsoft Sentinel'], ['elastic', 'Elastic Security']];

  SM.registerModule('liveaudit', {
    title: 'SIEM Live Audit', subtitle: 'Connect to an enterprise SIEM (read-only) through the local audit agent',
    render(body) {
      body.append(h('div', { class: 'demo-banner', style: { background: 'rgba(240,80,110,.08)', borderColor: 'rgba(240,80,110,.4)', color: '#ffd4dc' } }, '🔒', h('span', null, h('strong', 'Read-only by design. '), 'The live audit never modifies rules, creates rules, deletes offenses or deploys configuration. Credentials are handled by the local Python agent (localhost) and are never stored in this HTML file, localStorage or IndexedDB.')));
      const S = SM.Store; const conn = S.settings.siem_connection || null; const agent = S.settings.agent_url || 'http://127.0.0.1:8787';
      const tabs = SM.tabs([
        { label: 'Connection', render: () => connectionView(conn, agent) },
        { label: 'Audit workflow', render: () => workflowView(conn) },
        { label: 'Audit runs (' + S.auditRuns.length + ')', render: () => runsView() }
      ]);
      body.append(tabs);
    }
  });

  function connectionView(conn, agentUrl) {
    const wrap = h('div'); const f = Object.assign({ platform: 'qradar', host: '', ip: '', port: 443, api_version: '', auth_method: 'token', read_only: true, tls_verify: true, timeout: 30, page_size: 50, agent_url: agentUrl }, conn || {});
    const fld = (label, key, type = 'text', opts) => { let input; if (opts) input = h('select', { onChange: e => f[key] = e.target.value }, opts.map(o => h('option', { value: o.v, selected: f[key] === o.v }, o.l))); else input = h('input', { type, value: f[key], onInput: e => f[key] = type === 'number' ? Number(e.target.value) : e.target.value }); return h('div', { class: 'field' }, h('label', label), input); };
    wrap.append(ui.card('Local audit agent', h('div', null,
      h('div', { class: 'form-grid' }, fld('Agent URL (localhost)', 'agent_url')),
      h('div', { class: 'row', style: { marginTop: '8px' } }, h('button', { class: 'btn', onClick: () => pingAgent(f.agent_url) }, 'Test agent health'), h('span', { id: 'agent-status', class: 'small muted' }, 'Not checked')),
      h('div', { class: 'xs muted', style: { marginTop: '6px' } }, 'The agent (sentinel_matrix_agent.py) runs inside your network, binds to localhost, and brokers the SIEM API. Start it with: ', h('span', { class: 'mono' }, 'python sentinel_matrix_agent.py'))
    )));
    wrap.append(ui.card('SIEM connection', h('div', null,
      h('div', { class: 'form-grid' },
        fld('Platform', 'platform', 'text', PLATFORMS.map(p => ({ v: p[0], l: p[1] }))),
        fld('Hostname', 'host'), fld('IP address', 'ip'), fld('API port', 'port', 'number'),
        fld('API version', 'api_version'), fld('Auth method', 'auth_method', 'text', [{ v: 'token', l: 'API token / SEC' }, { v: 'bearer', l: 'Bearer / OAuth' }, { v: 'basic', l: 'Basic' }]),
      ),
      h('div', { class: 'row', style: { marginTop: '8px' } }, h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: f.read_only, disabled: true }), 'Read-only mode (enforced)'), h('label', { class: 'check' }, h('input', { type: 'checkbox', checked: f.tls_verify, onChange: e => f.tls_verify = e.target.checked }), 'Verify TLS certificate')),
      h('div', { class: 'field', style: { marginTop: '8px' } }, h('label', 'API token (sent to the local agent only; not persisted by this app)'), h('input', { type: 'password', id: 'siem-token', placeholder: '••••••••', autocomplete: 'off' })),
      h('div', { class: 'row', style: { marginTop: '10px' } },
        h('button', { class: 'btn primary', onClick: () => testConnection(f) }, 'Test connectivity & authenticate'),
        h('button', { class: 'btn', onClick: async () => { const c = Object.assign({}, f); delete c.token; c.status = conn ? conn.status : 'configured'; await SM.Store.setSetting('siem_connection', c); await SM.Store.setSetting('agent_url', f.agent_url); SM.toast('Connection saved (token not stored)', 'ok'); SM.App.refreshStatus(); } }, 'Save connection')
      )
    )));
    wrap.append(ui.card('Capability detection', h('div', { id: 'cap-box', class: 'small muted' }, 'Connect to detect which QRadar/SIEM fields and endpoints are available on this version.')));
    return wrap;
  }
  async function pingAgent(url) {
    const st = SM.$('#agent-status'); st.textContent = 'Checking ' + url + ' …';
    try { const r = await fetch(url.replace(/\/$/, '') + '/health', { method: 'GET' }); const j = await r.json(); st.innerHTML = ''; st.append(h('span', { class: 'tag green' }, 'Agent ' + (j.version || 'online')), ' ' + (j.status || 'healthy')); }
    catch (e) { st.innerHTML = ''; st.append(h('span', { class: 'tag amber' }, 'Agent not reachable'), ' — start sentinel_matrix_agent.py on this host. This is expected in a pure offline/standalone deployment.'); }
  }
  async function testConnection(f) {
    const token = SM.$('#siem-token') ? SM.$('#siem-token').value : '';
    const capBox = SM.$('#cap-box'); SM.clear(capBox).append('Contacting agent…');
    try {
      const r = await fetch(f.agent_url.replace(/\/$/, '') + '/api/siem/connect', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ platform: f.platform, host: f.host, ip: f.ip, port: f.port, api_version: f.api_version, auth_method: f.auth_method, token, tls_verify: f.tls_verify, read_only: true }) });
      const j = await r.json();
      if (!r.ok || j.error) throw new Error(j.error || ('HTTP ' + r.status));
      const c = Object.assign({}, f); delete c.token; c.status = 'connected'; c.api_version = j.api_version || f.api_version; c.capabilities = j.capabilities || {}; c.connected_at = SM.now();
      await SM.Store.setSetting('siem_connection', c); await SM.Store.setSetting('agent_url', f.agent_url);
      SM.clear(capBox).append(h('div', { class: 'row' }, h('span', { class: 'tag green' }, 'Connected'), 'API ' + (j.api_version || '?') + ' · ' + (j.deployment || f.platform)), h('div', { class: 'row', style: { marginTop: '8px', gap: '4px' } }, Object.entries(j.capabilities || {}).map(([k, v]) => h('span', { class: 'tag ' + (v ? 'green' : 'grey') }, (v ? '✓ ' : '✗ ') + k))));
      SM.toast('Connected to ' + f.platform + ' (read-only)', 'ok'); SM.App.refreshStatus();
    } catch (e) {
      SM.clear(capBox).append(h('span', { class: 'tag amber' }, 'Connection failed'), ' ' + e.message, h('div', { class: 'xs muted', style: { marginTop: '6px' } }, 'The standalone app has no direct network access to SIEMs by design — the local agent performs the request. If you have no agent running, use offline rule import instead (Rule Import & Inventory).'));
      const c = Object.assign({}, f); delete c.token; c.status = 'error'; await SM.Store.setSetting('siem_connection', c); SM.App.refreshStatus();
    }
  }

  function workflowView(conn) {
    const wrap = h('div');
    const steps = ['Configure', 'Test connectivity', 'Authenticate', 'Retrieve metadata', 'Retrieve rules', 'Retrieve log sources', 'Retrieve offenses/alerts', 'Normalise', 'Coverage analysis', 'Effectiveness', 'Gaps', 'Audit report'];
    wrap.append(h('div', { class: 'steps' }, steps.map((s, i) => h('span', { class: 'step', dataset: { i } }, (i + 1) + '. ' + s))));
    if (!conn || conn.status !== 'connected') wrap.append(h('div', { class: 'card' }, h('div', { class: 'row spread' }, h('div', null, h('strong', 'Not connected.'), h('div', { class: 'small muted' }, 'Configure and connect in the Connection tab, or run the audit in simulation mode to see the workflow with demo data.')), h('button', { class: 'btn', onClick: () => runAudit(conn, true) }, 'Run in simulation mode'))));
    else wrap.append(h('div', { class: 'card' }, h('div', { class: 'row spread' }, h('div', null, h('strong', 'Connected to ' + conn.platform), h('div', { class: 'small muted' }, conn.host || conn.ip)), h('button', { class: 'btn primary', onClick: () => runAudit(conn, false) }, '▶ Run live audit'))));
    wrap.append(h('div', { id: 'audit-out' }));
    return wrap;
  }
  async function runAudit(conn, simulate) {
    const out = SM.clear(SM.$('#audit-out')); const steps = SM.$$('.step');
    const prog = h('div', { class: 'progress' }, h('div', { style: { width: '0%' } })); const log = h('div', { class: 'small muted', style: { marginTop: '8px' } });
    out.append(ui.card('Audit in progress' + (simulate ? ' (simulation)' : ''), h('div', null, prog, log)));
    const mark = (n, txt) => { steps.forEach((s, i) => { s.classList.toggle('done', i < n); s.classList.toggle('active', i === n); }); prog.firstChild.style.width = Math.round(100 * n / 12) + '%'; log.textContent = txt; return new Promise(r => setTimeout(r, simulate ? 180 : 10)); };
    const run = { id: SM.uid('audit'), created_at: SM.now(), platform: conn ? conn.platform : 'qradar', mode: simulate ? 'simulation' : 'live', retrieved: {} };
    try {
      let data;
      if (simulate) { await mark(1, 'Simulating connectivity…'); await mark(2, 'Simulating authentication…'); await mark(3, 'Retrieving metadata…'); data = SM.Demo.simulatedAudit(); }
      else { const base = (conn.agent_url || SM.Store.settings.agent_url).replace(/\/$/, ''); const token = SM.$('#siem-token') ? SM.$('#siem-token').value : '';
        await mark(2, 'Authenticating via agent…'); await mark(3, 'Retrieving metadata…');
        const r = await fetch(base + '/api/siem/audit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ platform: conn.platform, host: conn.host, ip: conn.ip, port: conn.port, token, read_only: true, include: ['rules', 'log_sources', 'offenses', 'alerts'] }) });
        data = await r.json(); if (!r.ok || data.error) throw new Error(data.error || ('HTTP ' + r.status)); }
      await mark(4, 'Retrieved ' + (data.rules || []).length + ' rules…');
      // normalise rules through adapters
      const parsed = (data.rules || []).map(raw => { try { return SM.Import.adapters[conn && SM.Import.adapters[conn.platform] ? conn.platform : 'qradar'].parse([raw], { format: 'json', platform: (conn && conn.platform) || 'qradar', instance: (conn && conn.host) || 'live' })[0]; } catch (e) { return null; } }).filter(Boolean);
      await mark(5, 'Retrieved ' + (data.log_sources || []).length + ' log sources…');
      await mark(6, 'Retrieved ' + (data.offenses || []).length + ' offenses…');
      await mark(7, 'Normalising…');
      const batchId = SM.uid('livebatch');
      if (parsed.length) await SM.Store.addRules(parsed, batchId);
      if ((data.log_sources || []).length) await SM.Store.upsertLogSources(data.log_sources.map(SM.Demo.normLogSource));
      if ((data.offenses || []).length) await SM.Store.upsertOffenses(data.offenses);
      if ((data.alerts || []).length) await SM.Store.upsertAlerts(data.alerts);
      await mark(8, 'Running coverage analysis…'); const cov = await SM.runCoverage();
      await mark(9, 'Assessing operational effectiveness…');
      await mark(10, 'Identifying gaps…'); await SM.runGaps();
      await mark(11, 'Generating audit report…');
      run.retrieved = { rules: parsed.length, log_sources: (data.log_sources || []).length, offenses: (data.offenses || []).length, alerts: (data.alerts || []).length };
      run.composite = cov.summary.composite; run.critical_gaps = SM.Store.gaps.filter(g => g.risk_level === 'critical').length;
      await SM.DB.put('audit_runs', run); SM.Store.auditRuns.unshift(run);
      await mark(12, 'Done');
      SM.clear(out).append(ui.card('Audit complete' + (simulate ? ' (simulation data)' : ''), h('div', null,
        h('div', { class: 'grid kpi' }, ui.kpi('Rules', run.retrieved.rules), ui.kpi('Log sources', run.retrieved.log_sources), ui.kpi('Offenses', run.retrieved.offenses), ui.kpi('Composite coverage', run.composite, { color: 'cyan' }), ui.kpi('Critical gaps', run.critical_gaps, { color: run.critical_gaps ? 'red' : undefined })),
        h('div', { class: 'row', style: { marginTop: '12px' } }, h('button', { class: 'btn primary', onClick: () => SM.App.go('command') }, 'View dashboard'), h('button', { class: 'btn', onClick: () => SM.App.go('reports', { generate: 'qradar_audit' }) }, 'Generate audit report'))
      )));
      SM.toast('Live audit complete — composite ' + run.composite, 'ok');
    } catch (e) { SM.clear(out).append(h('div', { class: 'card' }, h('span', { class: 'tag red' }, 'Audit failed'), ' ' + e.message, h('div', { class: 'xs muted', style: { marginTop: '6px' } }, 'Ensure the local agent is running and reachable. For fully offline assessment, import rule exports instead.'))); }
  }
  function runsView() { const wrap = h('div'); if (!SM.Store.auditRuns.length) return ui.empty('No audit runs', 'Run a live or simulated audit to record results here.'); wrap.append(h('table', { class: 'plain' }, h('thead', h('tr', h('th', 'When'), h('th', 'Platform'), h('th', 'Mode'), h('th', 'Rules'), h('th', 'Offenses'), h('th', 'Composite'), h('th', 'Critical gaps'))), h('tbody', SM.Store.auditRuns.map(r => h('tr', h('td', SM.fmtDate(r.created_at)), h('td', r.platform), h('td', h('span', { class: 'tag ' + (r.mode === 'live' ? 'green' : 'grey') }, r.mode)), h('td', r.retrieved.rules), h('td', r.retrieved.offenses), h('td', r.composite), h('td', r.critical_gaps)))))); return wrap; }
})(globalThis.SM = globalThis.SM || {});
