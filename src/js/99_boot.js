/* SENTINEL MATRIX — boot sequence. */
(function (SM) {
  'use strict';
  async function boot() {
    const splash = document.getElementById('splash');
    try {
      await SM.DB.ready();
      await SM.FW.init();
      await SM.Scenarios.init();
      await SM.Store.loadAll();
      SM.App.build();
      // live refresh bindings
      ['rules:changed', 'coverage:changed', 'gaps:changed', 'generated:changed', 'logsources:changed', 'assets:changed', 'offenses:changed', 'alerts:changed', 'tests:changed'].forEach(ev => SM.on(ev, () => { if (['command'].includes(SM.App.current)) SM.App.go(SM.App.current, SM.App.params); }));
      const route = (location.hash || '').replace('#', '') || 'command';
      SM.App.go(SM.modules[route] ? route : 'command');
      if (splash) splash.remove();
      if (SM.DB.memMode()) SM.toast('IndexedDB is unavailable; running in in-memory mode (data will not persist across reloads).', 'warn', 8000);
    } catch (e) {
      console.error('Boot failure', e);
      if (splash) splash.innerHTML = '';
      document.body.appendChild(SM.h('div', { style: { padding: '40px', color: '#f0506e', fontFamily: 'monospace' } }, 'Boot error: ' + e.message, SM.h('pre', (e.stack || '').slice(0, 1000))));
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot); else boot();
  SM.boot = boot;
})(globalThis.SM = globalThis.SM || {});
