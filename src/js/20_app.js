/* SENTINEL MATRIX — application shell, router, sidebar, topbar. */
(function (SM) {
  'use strict';
  const h = SM.h;
  const ICON = (p) => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('class', 'ico'); s.setAttribute('fill', 'none'); s.setAttribute('stroke', 'currentColor'); s.setAttribute('stroke-width', '1.7'); s.setAttribute('stroke-linecap', 'round'); s.setAttribute('stroke-linejoin', 'round'); const path = document.createElementNS('http://www.w3.org/2000/svg', 'path'); path.setAttribute('d', p); s.appendChild(path); return s; };
  const ICONS = {
    command: 'M3 12h4l3-9 4 18 3-9h4', inventory: 'M4 7h16M4 12h16M4 17h16M8 3v18', coverage: 'M12 3v18M3 12h18M7 7l10 10M17 7L7 17', matrix: 'M3 3h7v7H3zM14 3h7v7h-7zM3 14h7v7H3zM14 14h7v7h-7z',
    gap: 'M12 2l9 16H3zM12 9v4M12 16h.01', eng: 'M14 7l3 3L7 20l-4 1 1-4zM18 3l3 3', gen: 'M12 3v18M3 8l9-5 9 5M3 16l9 5 9-5', validate: 'M9 12l2 2 4-4M21 12a9 9 0 11-18 0 9 9 0 0118 0z',
    live: 'M4 4h16v12H4zM8 20h8M12 16v4M8 10l2 2 4-4', offense: 'M12 2l3 7h7l-6 4 2 7-6-4-6 4 2-7-6-4h7z', logsrc: 'M4 6a8 3 0 0016 0 8 3 0 00-16 0zM4 6v12a8 3 0 0016 0V6',
    chain: 'M10 13a5 5 0 007 0l2-2a5 5 0 00-7-7l-1 1M14 11a5 5 0 00-7 0l-2 2a5 5 0 007 7l1-1', asset: 'M3 21h18M5 21V7l7-4 7 4v14M9 21v-6h6v6', lifecycle: 'M3 12a9 9 0 019-9 9 9 0 018 5M21 12a9 9 0 01-9 9 9 9 0 01-8-5M17 8h4V4M7 16H3v4',
    reports: 'M7 3h10l4 4v14H3V3zM14 3v5h5M8 13h8M8 17h5', framework: 'M12 2L2 7l10 5 10-5zM2 17l10 5 10-5M2 12l10 5 10-5', settings: 'M12 15a3 3 0 100-6 3 3 0 000 6zM19 12l2 1-2 3-2-1a7 7 0 01-2 1l-1 2h-4l-1-2a7 7 0 01-2-1l-2 1-2-3 2-1a7 7 0 010-2l-2-1 2-3 2 1a7 7 0 012-1l1-2h4l1 2a7 7 0 012 1l2-1 2 3-2 1a7 7 0 010 2z'
  };
  const NAV = [
    { sec: 'Operations' },
    { id: 'command', label: 'Command Centre', icon: 'command' },
    { id: 'inventory', label: 'Rule Import & Inventory', icon: 'inventory' },
    { id: 'coverage', label: 'Detection Coverage', icon: 'coverage' },
    { id: 'matrix', label: 'ATT&CK Matrix', icon: 'matrix' },
    { id: 'gaps', label: 'Gap Analysis', icon: 'gap' },
    { sec: 'Engineering' },
    { id: 'engineering', label: 'Detection Engineering', icon: 'eng' },
    { id: 'generator', label: 'Rule Generator', icon: 'gen' },
    { id: 'validation', label: 'Detection Validation', icon: 'validate' },
    { id: 'lifecycle', label: 'Detection Lifecycle', icon: 'lifecycle' },
    { sec: 'SIEM & Telemetry' },
    { id: 'liveaudit', label: 'SIEM Live Audit', icon: 'live' },
    { id: 'offenses', label: 'Offense & Alert Analytics', icon: 'offense' },
    { id: 'logsources', label: 'Log Source Intelligence', icon: 'logsrc' },
    { id: 'chain', label: 'Attack Chain Analysis', icon: 'chain' },
    { id: 'assets', label: 'Enterprise Asset Context', icon: 'asset' },
    { sec: 'Knowledge & Output' },
    { id: 'reports', label: 'Reports & Exports', icon: 'reports' },
    { id: 'framework', label: 'Framework Database', icon: 'framework' },
    { id: 'settings', label: 'Settings', icon: 'settings' }
  ];
  SM.modules = {}; // id -> { render(container), title, subtitle }
  SM.registerModule = (id, mod) => { SM.modules[id] = mod; };

  const App = { current: null, navEls: {} };
  SM.App = App;

  App.build = () => {
    const root = SM.$('#app');
    // Sidebar
    const brand = h('div', { class: 'brand' }, SM.logo(), h('div', null, h('div', { class: 'name' }, 'SENTINEL'), h('div', { class: 'tag' }, 'MATRIX')));
    const nav = h('div', { class: 'nav' }); let n = 0;
    for (const item of NAV) { if (item.sec) { nav.appendChild(h('div', { class: 'nav-section' }, item.sec)); continue; } n++; const navItem = h('div', { class: 'nav-item', dataset: { route: item.id }, title: item.label, onClick: () => App.go(item.id) }, ICON(ICONS[item.icon] || ICONS.command), h('span', { class: 'label' }, item.label), h('span', { class: 'n' }, n)); App.navEls[item.id] = navItem; nav.appendChild(navItem); }
    const foot = h('div', { class: 'sidebar-foot' }, h('div', { class: 'txt' }, 'Offline detection intelligence'), h('div', { class: 'ver' }, 'v' + SM.VERSION + ' · ' + (SM.DB.memMode() ? 'in-memory' : 'IndexedDB')));
    SM.clear(SM.$('#sidebar')).append(brand, nav, foot);
    // Topbar
    App.buildTopbar();
    SM.on('notifications', App.renderNotifBadge);
  };

  App.buildTopbar = () => {
    const tb = SM.$('#topbar'); SM.clear(tb);
    const collapse = h('button', { class: 'icon-btn', title: 'Toggle sidebar', onClick: () => SM.$('#app').classList.toggle('collapsed') }, '☰');
    const search = h('div', { id: 'global-search' }, h('span', { class: 'icon' }, '⌕'), h('input', { type: 'text', placeholder: 'Search rules, techniques, gaps, assets, offenses…  (press /)', autocomplete: 'off', spellcheck: 'false', onInput: (e) => App.search(e.target.value), onFocus: (e) => e.target.value && App.search(e.target.value) }), h('div', { id: 'search-results' }));
    const siemPill = h('div', { class: 'status-pill', id: 'siem-pill' }, h('span', { class: 'dot' }), 'SIEM: offline');
    const modePill = h('div', { class: 'status-pill info', id: 'mode-pill' }, h('span', { class: 'dot' }), 'Offline audit mode');
    const wsPill = h('div', { class: 'status-pill', id: 'ws-pill', title: 'Active workspace / profile' }, h('span', { class: 'dot' }), 'AD Enterprise');
    const tsPill = h('div', { class: 'status-pill', id: 'ts-pill', title: 'Last assessment timestamp' }, h('span', { class: 'dot' }), 'Not assessed');
    const notif = h('button', { class: 'icon-btn', id: 'notif-btn', title: 'Notifications', onClick: App.openNotifications }, '🔔');
    const profile = h('button', { class: 'icon-btn', title: 'Analyst', onClick: () => App.go('settings') }, '👤');
    tb.append(collapse, SM.$('#app').classList.contains('collapsed') ? null : h('div', { style: { width: '6px' } }), search, siemPill, modePill, wsPill, tsPill, notif, profile);
    App.refreshStatus();
  };
  App.refreshStatus = () => {
    const S = SM.Store; const p = S.profile();
    const ws = SM.$('#ws-pill'); if (ws) SM.clear(ws).append(h('span', { class: 'dot' }), (p ? p.name : 'No profile'));
    const ts = SM.$('#ts-pill'); if (ts) SM.clear(ts).append(h('span', { class: 'dot' }), S.coverage ? 'Assessed ' + SM.fmtDate(S.coverage.assessed_at) : 'Not assessed');
    const conn = S.settings.siem_connection; const sp = SM.$('#siem-pill'); if (sp) { SM.clear(sp); sp.className = 'status-pill ' + (conn && conn.status === 'connected' ? 'ok' : conn && conn.status === 'error' ? 'err' : ''); sp.append(h('span', { class: 'dot' }), 'SIEM: ' + (conn ? (conn.platform || 'qradar') + ' ' + conn.status : 'offline')); }
    App.renderNotifBadge();
  };
  App.renderNotifBadge = () => { const btn = SM.$('#notif-btn'); if (!btn) return; const unread = SM.notifications.filter(n => !n.read).length; const ex = SM.$('.badge-count', btn); if (ex) ex.remove(); if (unread) btn.appendChild(h('span', { class: 'badge-count' }, unread > 99 ? '99+' : unread)); };
  App.openNotifications = () => { SM.notifications.forEach(n => n.read = true); App.renderNotifBadge(); SM.drawer.open('Notifications', SM.notifications.length ? h('div', null, SM.notifications.map(n => h('div', { class: 'card', style: { marginBottom: '8px', borderLeft: '3px solid var(--' + (n.kind === 'err' ? 'red' : n.kind === 'warn' ? 'amber' : n.kind === 'ok' ? 'green' : 'cyan') + ')' } }, h('div', n.msg), h('div', { class: 'xs muted' }, SM.fmtDate(n.at))))) : h('div', { class: 'empty' }, 'No notifications.')); };

  App.search = (q) => { const box = SM.$('#search-results'); if (!box) return; if (!q || q.length < 2) { box.classList.remove('open'); return; } const res = SM.Search.query(q, 30); SM.clear(box); if (!res.length) { box.appendChild(h('div', { class: 'sr-item' }, h('span', { class: 'muted' }, 'No matches'))); } else res.forEach(d => box.appendChild(h('div', { class: 'sr-item', onClick: () => { box.classList.remove('open'); SM.$('#global-search input').value = ''; App.openSearchResult(d); } }, h('span', { class: 'kind' }, d.kind), h('div', null, h('div', SM.truncate(d.title, 60)), h('div', { class: 'sub' }, SM.truncate(d.sub, 70)))))); box.classList.add('open'); };
  App.openSearchResult = (d) => { const map = { rule: 'inventory', technique: 'matrix', gap: 'gaps', 'log source': 'logsources', asset: 'assets', offense: 'offenses', scenario: 'generator' }; App.go(map[d.kind] || 'command', { focus: d.ref }); };
  document.addEventListener('click', (e) => { const sr = SM.$('#search-results'); if (sr && !e.target.closest('#global-search')) sr.classList.remove('open'); });
  document.addEventListener('keydown', (e) => { if (e.key === '/' && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); const i = SM.$('#global-search input'); if (i) i.focus(); } if (e.key === 'Escape') { SM.$('#search-results') && SM.$('#search-results').classList.remove('open'); SM.drawer.close(); } });

  App.go = (id, params = {}) => {
    if (!SM.modules[id]) { SM.toast('Module not available: ' + id, 'warn'); id = 'command'; }
    App.current = id; App.params = params;
    Object.entries(App.navEls).forEach(([k, el]) => el.classList.toggle('active', k === id));
    const main = SM.$('#main'); SM.clear(main); main.scrollTop = 0;
    const mod = SM.modules[id];
    const head = h('div', { class: 'page-head' }, h('div', null, h('h1', mod.title), mod.subtitle ? h('div', { class: 'sub' }, mod.subtitle) : null), h('div', { class: 'actions', id: 'page-actions' }));
    main.appendChild(head);
    const body = h('div', { id: 'page-body' }); main.appendChild(body);
    try { mod.render(body, params, SM.$('#page-actions')); } catch (e) { console.error(e); body.appendChild(h('div', { class: 'empty' }, h('h4', 'Module error'), h('div', { class: 'small' }, SM.str(e.message)))); }
    try { location.hash = id; } catch (e) { }
  };
  SM.on('store:loaded', App.refreshStatus); SM.on('coverage:changed', App.refreshStatus); SM.on('settings:changed', App.refreshStatus);

  SM.logo = () => { const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg'); s.setAttribute('viewBox', '0 0 48 48'); s.setAttribute('class', 'logo'); const g = `<defs><linearGradient id="lg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#19d3f3"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs><path d="M24 3l17 6v11c0 11-7 20-17 24C14 40 7 31 7 20V9z" fill="none" stroke="url(#lg)" stroke-width="2.4"/><path d="M24 14v20M15 24h18M18 18l12 12M30 18L18 30" stroke="#19d3f3" stroke-width="1.6" stroke-linecap="round" opacity="0.85"/><circle cx="24" cy="24" r="3.4" fill="#19d3f3"/>`; s.innerHTML = g; return s; };

  // Shared page helpers used by modules
  SM.ui = {
    kpi(label, value, { color, onClick, delta } = {}) { return h('div', { class: 'kpi-card' + (color ? ' c-' + color : ''), onClick: onClick, role: onClick ? 'button' : null, tabindex: onClick ? 0 : null }, h('div', { class: 'label' }, label), h('div', { class: 'value' }, SM.str(value)), delta ? h('div', { class: 'delta' }, delta) : null); },
    card(title, body, hint) { return h('div', { class: 'card' }, title ? h('h3', title, hint ? h('span', { class: 'hint' }, hint) : null) : null, body); },
    demoBanner() { return SM.Store.demoLoaded ? h('div', { class: 'demo-banner' }, '⚠', h('span', null, h('strong', 'DEMO DATA loaded. '), 'All figures below are illustrative sample data, not a real assessment. Clear it in Settings → Data Management before using live imports.')) : null; },
    empty(title, msg, action) { return h('div', { class: 'empty' }, h('h4', title), h('div', { class: 'small' }, msg), action ? h('div', { style: { marginTop: '12px' } }, action) : null); },
    covTag(c) { const cov = SM.COVERAGE[c] || SM.COVERAGE.UNKNOWN; const cls = { VALIDATED: 'green', FULLY_COVERED: 'cyan', PARTIALLY_COVERED: 'amber', WEAK_COVERAGE: 'orange', UNVALIDATED_COVERAGE: 'orange', NOT_COVERED: 'red', NOT_APPLICABLE: 'grey', UNKNOWN: 'grey' }[c] || 'grey'; return h('span', { class: 'tag ' + cls }, cov.label); },
    sevTag(s) { s = SM.normSeverity(s); return h('span', { class: 'tag ' + ({ critical: 'red', high: 'orange', medium: 'amber', low: 'cyan', informational: 'grey', unknown: 'grey' }[s]) }, s); },
    techLink(id, label) { return h('a', { href: '#matrix', onClick: (e) => { e.preventDefault(); SM.App.go('matrix', { focus: id }); } }, label || id); },
    riskTag(level) { return h('span', { class: 'tag ' + ({ critical: 'red', high: 'orange', medium: 'amber', low: 'cyan' }[level] || 'grey') }, level); }
  };
})(globalThis.SM = globalThis.SM || {});
