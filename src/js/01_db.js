/* SENTINEL MATRIX — IndexedDB persistence layer with schema versioning, migrations, backup/restore. */
(function (SM) {
  'use strict';
  const DB_NAME = 'sentinel_matrix';
  const SCHEMA_VERSION = 3;
  // store name → { keyPath, indexes: [[name, keyPath, opts]] }
  const STORES = {
    rules: { keyPath: 'rule_id', indexes: [['source_platform', 'source_platform'], ['severity', 'severity'], ['enabled_status', 'enabled_status'], ['fingerprint', 'fingerprint'], ['techniques', 'attack_techniques', { multiEntry: true }], ['lifecycle', 'lifecycle_stage'], ['batch', 'import_batch']] },
    import_batches: { keyPath: 'batch_id', indexes: [['created', 'created_at']] },
    attack_techniques: { keyPath: 'id', indexes: [['tactics', 'tactics', { multiEntry: true }], ['parent', 'parent']] },
    attack_tactics: { keyPath: 'id' },
    attack_datasources: { keyPath: 'id' },
    d3fend: { keyPath: 'id' },
    capec: { keyPath: 'id' },
    killchain: { keyPath: 'id' },
    sigma_rules: { keyPath: 'id', indexes: [['techniques', 'techniques', { multiEntry: true }]] },
    scenario_templates: { keyPath: 'id', indexes: [['technique', 'technique']] },
    generated_rules: { keyPath: 'id', indexes: [['technique', 'technique'], ['platform', 'target_platform'], ['lifecycle', 'lifecycle_stage']] },
    log_sources: { keyPath: 'id', indexes: [['type', 'source_type'], ['zone', 'zone'], ['health', 'health_status']] },
    assets: { keyPath: 'asset_id', indexes: [['zone', 'zone'], ['criticality', 'criticality'], ['bu', 'business_unit']] },
    zones: { keyPath: 'id' },
    coverage: { keyPath: 'technique_id', indexes: [['classification', 'classification']] },
    gaps: { keyPath: 'gap_id', indexes: [['technique', 'technique_id'], ['priority', 'priority_score'], ['status', 'status']] },
    validation_tests: { keyPath: 'test_id', indexes: [['rule', 'rule_id'], ['status', 'status']] },
    offenses: { keyPath: 'id', indexes: [['status', 'status'], ['severity', 'severity']] },
    alerts: { keyPath: 'id', indexes: [['rule', 'rule_id']] },
    reports: { keyPath: 'id', indexes: [['created', 'created_at']] },
    annotations: { keyPath: 'id', indexes: [['target', 'target_id']] },
    lifecycle_events: { keyPath: 'id', indexes: [['rule', 'rule_id'], ['at', 'at']] },
    framework_versions: { keyPath: 'id' },
    saved_filters: { keyPath: 'id' },
    audit_runs: { keyPath: 'id', indexes: [['created', 'created_at']] },
    settings: { keyPath: 'key' }
  };
  SM.DB_STORES = Object.keys(STORES);

  let dbp = null;
  const hasIDB = typeof indexedDB !== 'undefined';

  // In-memory fallback (used in Node tests or when IndexedDB is unavailable, e.g. file:// in some private modes)
  const mem = {}; SM.DB_STORES.forEach(s => mem[s] = new Map());
  let memMode = !hasIDB;

  function open() {
    if (dbp) return dbp;
    dbp = new Promise((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, SCHEMA_VERSION);
      req.onupgradeneeded = (ev) => {
        const db = req.result; const oldV = ev.oldVersion;
        SM.migrations && SM.migrations.log && SM.migrations.log(oldV, SCHEMA_VERSION);
        for (const [name, def] of Object.entries(STORES)) {
          let store;
          if (!db.objectStoreNames.contains(name)) store = db.createObjectStore(name, { keyPath: def.keyPath });
          else store = req.transaction.objectStore(name);
          for (const [iname, kp, opts] of (def.indexes || [])) if (!store.indexNames.contains(iname)) store.createIndex(iname, kp, opts || {});
        }
      };
      req.onsuccess = () => { const db = req.result; db.onversionchange = () => db.close(); resolve(db); };
      req.onerror = () => { console.warn('IndexedDB unavailable, falling back to in-memory store', req.error); memMode = true; resolve(null); };
      req.onblocked = () => console.warn('IndexedDB open blocked');
    });
    return dbp;
  }
  const tx = async (store, mode, fn) => {
    const db = await open(); if (!db) return fn(null);
    return new Promise((resolve, reject) => { const t = db.transaction(store, mode); const s = t.objectStore(store); let out; try { out = fn(s); } catch (e) { reject(e); return; } t.oncomplete = () => resolve(out && out.__result !== undefined ? out.__result : out); t.onerror = () => reject(t.error); t.onabort = () => reject(t.error || new Error('transaction aborted')); });
  };
  const reqp = (r) => new Promise((res, rej) => { r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error); });

  const DB = {
    SCHEMA_VERSION, memMode: () => memMode,
    async ready() { if (memMode) return true; await open(); return true; },
    async put(store, obj) { if (memMode) { mem[store].set(obj[STORES[store].keyPath], obj); return obj; } await tx(store, 'readwrite', s => s.put(obj)); return obj; },
    async bulkPut(store, objs, onProgress) {
      if (memMode) { objs.forEach(o => mem[store].set(o[STORES[store].keyPath], o)); return objs.length; }
      const CH = 500; const db = await open();
      for (let i = 0; i < objs.length; i += CH) {
        const chunk = objs.slice(i, i + CH);
        await new Promise((res, rej) => { const t = db.transaction(store, 'readwrite'); const s = t.objectStore(store); chunk.forEach(o => s.put(o)); t.oncomplete = res; t.onerror = () => rej(t.error); });
        onProgress && onProgress(Math.min(i + CH, objs.length), objs.length);
      }
      return objs.length;
    },
    async get(store, key) { if (memMode) return mem[store].get(key) || null; const db = await open(); return reqp(db.transaction(store).objectStore(store).get(key)).then(v => v || null); },
    async getAll(store) { if (memMode) return Array.from(mem[store].values()); const db = await open(); return reqp(db.transaction(store).objectStore(store).getAll()); },
    async getByIndex(store, index, value) { if (memMode) { const kp = STORES[store].indexes.find(i => i[0] === index)[1]; return Array.from(mem[store].values()).filter(o => Array.isArray(o[kp]) ? o[kp].includes(value) : o[kp] === value); } const db = await open(); return reqp(db.transaction(store).objectStore(store).index(index).getAll(value)); },
    async count(store) { if (memMode) return mem[store].size; const db = await open(); return reqp(db.transaction(store).objectStore(store).count()); },
    async delete(store, key) { if (memMode) { mem[store].delete(key); return; } await tx(store, 'readwrite', s => s.delete(key)); },
    async clear(store) { if (memMode) { mem[store].clear(); return; } await tx(store, 'readwrite', s => s.clear()); },
    async clearAll() { for (const s of SM.DB_STORES) if (s !== 'settings') await DB.clear(s); },
    async setting(key, value) { if (value === undefined) { const r = await DB.get('settings', key); return r ? r.value : undefined; } await DB.put('settings', { key, value, updated_at: SM.now() }); return value; },
    async exportWorkspace({ includeFrameworks = true } = {}) {
      const out = { app: SM.APP_NAME, version: SM.VERSION, schema_version: SCHEMA_VERSION, exported_at: SM.now(), stores: {} };
      const skip = new Set(includeFrameworks ? [] : ['attack_techniques', 'attack_tactics', 'attack_datasources', 'd3fend', 'capec', 'killchain', 'sigma_rules']);
      for (const s of SM.DB_STORES) { if (skip.has(s)) continue; let rows = await DB.getAll(s); if (s === 'settings') rows = rows.filter(r => !/token|secret|password|credential/i.test(r.key)); out.stores[s] = rows; }
      out.integrity = SM.hash(JSON.stringify(out.stores));
      return out;
    },
    async importWorkspace(data, { merge = false } = {}) {
      if (!data || data.app !== SM.APP_NAME || !data.stores) throw new Error('Not a Sentinel Matrix workspace backup');
      if (data.integrity && SM.hash(JSON.stringify(data.stores)) !== data.integrity) throw new Error('Integrity check failed: backup content does not match its checksum');
      if (data.schema_version > SCHEMA_VERSION) throw new Error('Backup was created with a newer schema version (' + data.schema_version + ')');
      const report = {};
      for (const [s, rows] of Object.entries(data.stores)) { if (!STORES[s]) { report[s] = 'skipped (unknown store)'; continue; } if (!merge) await DB.clear(s); const valid = rows.filter(r => r && r[STORES[s].keyPath] !== undefined); await DB.bulkPut(s, valid); report[s] = valid.length; }
      return report;
    },
    async storageEstimate() { if (typeof navigator !== 'undefined' && navigator.storage && navigator.storage.estimate) { const e = await navigator.storage.estimate(); return { usage: e.usage || 0, quota: e.quota || 0 }; } return { usage: 0, quota: 0 }; },
    async integrityCheck() {
      const issues = []; const rules = await DB.getAll('rules'); const ids = new Set();
      for (const r of rules) { if (!r.rule_id) issues.push({ store: 'rules', issue: 'missing rule_id' }); if (ids.has(r.rule_id)) issues.push({ store: 'rules', issue: 'duplicate key ' + r.rule_id }); ids.add(r.rule_id); if (!Array.isArray(r.attack_techniques)) issues.push({ store: 'rules', issue: 'attack_techniques not array on ' + r.rule_id }); }
      const cov = await DB.getAll('coverage'); const techIds = new Set((await DB.getAll('attack_techniques')).map(t => t.id));
      for (const c of cov) if (!techIds.has(c.technique_id)) issues.push({ store: 'coverage', issue: 'coverage row for unknown technique ' + c.technique_id });
      const gaps = await DB.getAll('gaps'); for (const g of gaps) if (!techIds.has(g.technique_id)) issues.push({ store: 'gaps', issue: 'gap for unknown technique ' + g.technique_id });
      return { checked: { rules: rules.length, coverage: cov.length, gaps: gaps.length }, issues };
    }
  };
  SM.DB = DB;
  SM.migrations = { history: [], log(from, to) { this.history.push({ from, to, at: SM.now() }); } };
})(globalThis.SM = globalThis.SM || {});
