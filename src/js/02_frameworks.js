/* SENTINEL MATRIX — framework database: ATT&CK / D3FEND / CAPEC / Kill Chain loading, STIX import, lookups. */
(function (SM) {
  'use strict';
  const FW = {
    attack: null, d3fend: null, capec: null, killchain: null, telemetry: null, eventIds: null, logSourceCatalog: null, profiles: null, sigmaPack: null,
    byId: new Map(), byTactic: new Map(), dcById: new Map(), tacticById: new Map(), children: new Map(), loaded: false,

    // Bundled data is injected at build time as JSON inside <script type="application/json"> tags; in Node tests it is passed in directly.
    readBundled(id) {
      if (SM.BUNDLED && SM.BUNDLED[id]) return SM.BUNDLED[id];
      if (typeof document === 'undefined') return null;
      const el = document.getElementById('data-' + id); if (!el) return null;
      try { return SM.safeJSON(el.textContent); } catch (e) { console.error('bundled data parse failure', id, e); return null; }
    },

    async init() {
      // Prefer persisted (possibly updated) framework data; fall back to bundled.
      const persistedTechs = await SM.DB.getAll('attack_techniques');
      const bundled = FW.readBundled('attack');
      if (persistedTechs.length) {
        FW.attack = { tactics: await SM.DB.getAll('attack_tactics'), techniques: persistedTechs, data_components: await SM.DB.getAll('attack_datasources'), version: (await SM.DB.setting('attack_version')) || (bundled && bundled.version), dataset_kind: (await SM.DB.setting('attack_kind')) || 'persisted' };
        FW.attack.platforms = SM.uniq(persistedTechs.flatMap(t => t.platforms || [])).sort();
        FW.attack.stats = { tactics: FW.attack.tactics.length, techniques: persistedTechs.filter(t => !t.is_subtechnique).length, subtechniques: persistedTechs.filter(t => t.is_subtechnique).length };
        FW.attack.framework = (bundled && bundled.framework) || 'MITRE ATT&CK Enterprise'; FW.attack.note = bundled && bundled.note;
      } else if (bundled) {
        FW.attack = bundled;
        await FW.persistAttack(bundled, { source: 'bundled' });
      } else FW.attack = { tactics: [], techniques: [], data_components: [] };
      FW.d3fend = (await SM.DB.getAll('d3fend')); if (!FW.d3fend.length) { const b = FW.readBundled('d3fend'); if (b) { FW.d3fend = b.techniques; await SM.DB.bulkPut('d3fend', b.techniques); await FW.recordVersion('D3FEND', b.version, 'bundled', b.techniques.length); } }
      FW.capec = (await SM.DB.getAll('capec')); if (!FW.capec.length) { const b = FW.readBundled('capec'); if (b) { FW.capec = b.patterns; await SM.DB.bulkPut('capec', b.patterns); await FW.recordVersion('CAPEC', b.version, 'bundled', b.patterns.length); } }
      FW.killchain = (await SM.DB.getAll('killchain')); if (!FW.killchain.length) { const b = FW.readBundled('killchain'); if (b) { FW.killchain = b.phases; await SM.DB.bulkPut('killchain', b.phases); } }
      FW.sigmaPack = (await SM.DB.getAll('sigma_rules')); if (!FW.sigmaPack.length) { const b = FW.readBundled('sigma'); if (b) { FW.sigmaPack = b.rules; await SM.DB.bulkPut('sigma_rules', b.rules); await FW.recordVersion('Sigma sample pack', b.version, 'bundled', b.rules.length); } }
      FW.telemetry = FW.readBundled('telemetry') || { data_components: FW.attack.data_components || [] };
      FW.eventIds = FW.readBundled('eventids') || { windows: [], sysmon: [], auditd: [] };
      FW.logSourceCatalog = FW.readBundled('logsources') || { types: [], zones: [] };
      const savedProfiles = await SM.DB.setting('environment_profiles');
      FW.profiles = savedProfiles || (FW.readBundled('profiles') || { profiles: [] }).profiles;
      FW.index(); FW.loaded = true; SM.emit('frameworks:loaded');
    },

    async persistAttack(ds, { source }) {
      await SM.DB.clear('attack_techniques'); await SM.DB.clear('attack_tactics'); await SM.DB.clear('attack_datasources');
      await SM.DB.bulkPut('attack_techniques', ds.techniques); await SM.DB.bulkPut('attack_tactics', ds.tactics); await SM.DB.bulkPut('attack_datasources', ds.data_components || []);
      await SM.DB.setting('attack_version', ds.version); await SM.DB.setting('attack_kind', ds.dataset_kind || source);
      await FW.recordVersion('ATT&CK Enterprise', ds.version, source, ds.techniques.length, ds);
    },
    async recordVersion(framework, version, source, count, snapshot) {
      const rec = { id: SM.uid('fwv'), framework, version: version || 'unknown', source, record_count: count, imported_at: SM.now(), active: true };
      const all = await SM.DB.getAll('framework_versions');
      for (const v of all) if (v.framework === framework && v.active) { v.active = false; await SM.DB.put('framework_versions', v); }
      if (snapshot && framework === 'ATT&CK Enterprise') { // keep compact rollback snapshot (ids/names/tactics/platforms/dcs only)
        rec.snapshot = { version: snapshot.version, dataset_kind: snapshot.dataset_kind, tactics: snapshot.tactics, techniques: snapshot.techniques, data_components: snapshot.data_components };
      }
      await SM.DB.put('framework_versions', rec); return rec;
    },
    async rollback(versionId) {
      const v = await SM.DB.get('framework_versions', versionId); if (!v || !v.snapshot) throw new Error('No rollback snapshot stored for this version');
      await FW.persistAttack(v.snapshot, { source: 'rollback:' + v.version }); FW.attack = v.snapshot; FW.index(); SM.emit('frameworks:loaded');
    },

    index() {
      FW.byId.clear(); FW.byTactic.clear(); FW.dcById.clear(); FW.tacticById.clear(); FW.children.clear();
      for (const t of FW.attack.tactics || []) FW.tacticById.set(t.id, t);
      for (const d of FW.attack.data_components || []) FW.dcById.set(d.id, d);
      for (const t of FW.attack.techniques || []) {
        FW.byId.set(t.id, t);
        for (const ta of t.tactics || []) { if (!FW.byTactic.has(ta)) FW.byTactic.set(ta, []); FW.byTactic.get(ta).push(t); }
        if (t.parent) { if (!FW.children.has(t.parent)) FW.children.set(t.parent, []); FW.children.get(t.parent).push(t); }
      }
      for (const [, arr] of FW.byTactic) arr.sort((a, b) => a.id.localeCompare(b.id));
    },
    technique(id) { return FW.byId.get(SM.str(id).toUpperCase()) || null; },
    tacticsOrdered() { return (FW.attack.tactics || []).slice().sort((a, b) => a.order - b.order); },
    techniquesForTactic(tacticId, { parentsOnly = false } = {}) { const arr = FW.byTactic.get(tacticId) || []; return parentsOnly ? arr.filter(t => !t.is_subtechnique) : arr; },
    subtechniques(parentId) { return FW.children.get(parentId) || []; },
    allTechniques() { return FW.attack.techniques || []; },
    tacticName(id) { const t = FW.tacticById.get(id); return t ? t.name : id; },
    tacticShort(id) { const t = FW.tacticById.get(id); return t ? t.shortname : id; },
    // Telemetry requirements for a technique: data components → log source types, event ids
    telemetryFor(techId) {
      const t = FW.technique(techId); if (!t) return { components: [], logSourceTypes: [], windowsEventIds: [], sysmonEventIds: [], auditdKeys: [] };
      const comps = (t.data_components || []).map(c => FW.dcById.get(c.id) || c);
      return {
        components: comps,
        logSourceTypes: SM.uniq(comps.flatMap(c => c.log_source_types || [])),
        windowsEventIds: SM.uniq(comps.flatMap(c => c.windows_event_ids || [])),
        sysmonEventIds: SM.uniq(comps.flatMap(c => c.sysmon_event_ids || [])),
        auditdKeys: SM.uniq(comps.flatMap(c => c.auditd_keys || []))
      };
    },
    d3fendFor(techId) { const p = SM.parentTechnique(techId); return (FW.d3fend || []).filter(d => (d.attack_techniques || []).some(x => x === techId || x === p)); },
    capecFor(techId) { const p = SM.parentTechnique(techId); return (FW.capec || []).filter(d => (d.attack_techniques || []).some(x => x === techId || x === p)); },
    killchainFor(tacticId) { return (FW.killchain || []).filter(k => (k.attack_tactics || []).includes(tacticId)); },
    sigmaFor(techId) { return (FW.sigmaPack || []).filter(s => (s.techniques || []).includes(techId) || (s.techniques || []).includes(SM.parentTechnique(techId))); },
    logSourceType(id) { return (FW.logSourceCatalog.types || []).find(t => t.id === id) || { id, name: id, platform: 'Unknown', category: 'unknown' }; },
    profile(id) { return (FW.profiles || []).find(p => p.id === id) || null; },
    async saveProfiles(list) { FW.profiles = list; await SM.DB.setting('environment_profiles', list); },

    // ---- STIX 2.1 import (official MITRE enterprise-attack bundle) ----
    parseStix(bundle) {
      if (!bundle || !Array.isArray(bundle.objects)) throw new Error('Not a STIX bundle (missing objects array)');
      const objs = bundle.objects; const tacticsByShort = new Map(); const tactics = [];
      const extId = (o) => ((o.external_references || []).find(r => r.source_name === 'mitre-attack') || {}).external_id;
      for (const o of objs) if (o.type === 'x-mitre-tactic' && !o.revoked && !o.x_mitre_deprecated) { const id = extId(o); if (!id) continue; const t = { id, shortname: o.x_mitre_shortname, name: o.name, description: SM.truncate(o.description, 300), order: 99 }; tactics.push(t); tacticsByShort.set(o.x_mitre_shortname, id); }
      const ORDER = ['reconnaissance', 'resource-development', 'initial-access', 'execution', 'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access', 'discovery', 'lateral-movement', 'collection', 'command-and-control', 'exfiltration', 'impact'];
      tactics.forEach(t => { const i = ORDER.indexOf(t.shortname); t.order = i < 0 ? 99 : i; });
      const dcs = new Map(); const dsById = new Map();
      for (const o of objs) if (o.type === 'x-mitre-data-source') dsById.set(o.id, o.name);
      for (const o of objs) if (o.type === 'x-mitre-data-component') dcs.set(o.id, { stix: o.id, id: 'DC-' + SM.slug(o.name), source: dsById.get(o.x_mitre_data_source_ref) || 'Unknown', component: o.name });
      const techByStix = new Map(); const techniques = [];
      for (const o of objs) if (o.type === 'attack-pattern' && !o.revoked && !o.x_mitre_deprecated) {
        const id = extId(o); if (!id) continue;
        const t = { id, name: o.name, tactics: (o.kill_chain_phases || []).filter(k => k.kill_chain_name === 'mitre-attack').map(k => tacticsByShort.get(k.phase_name)).filter(Boolean), platforms: o.x_mitre_platforms || [], description: SM.truncate(o.description || '', 1200), parent: id.includes('.') ? id.split('.')[0] : null, is_subtechnique: !!o.x_mitre_is_subtechnique, data_components: [], detection_strategy: SM.truncate(o.x_mitre_detection || '', 1200), stix: o.id };
        techniques.push(t); techByStix.set(o.id, t);
      }
      for (const o of objs) if (o.type === 'relationship' && o.relationship_type === 'detects') { const dc = dcs.get(o.source_ref); const t = techByStix.get(o.target_ref); if (dc && t && !t.data_components.some(x => x.id === dc.id)) t.data_components.push({ id: dc.id, source: dc.source, component: dc.component }); }
      const names = new Map(techniques.map(t => [t.id, t.name])); techniques.forEach(t => { if (t.parent) t.parent_name = names.get(t.parent); delete t.stix; });
      // map STIX data components onto bundled telemetry knowledge when names match
      const bundledTel = (FW.telemetry && FW.telemetry.data_components) || [];
      const data_components = Array.from(dcs.values()).map(dc => { const k = bundledTel.find(b => b.component.toLowerCase() === dc.component.toLowerCase() && b.source.toLowerCase() === dc.source.toLowerCase()); return { id: dc.id, source: dc.source, component: dc.component, log_source_types: k ? k.log_source_types : [], windows_event_ids: k ? k.windows_event_ids : [], sysmon_event_ids: k ? k.sysmon_event_ids : [], auditd_keys: k ? k.auditd_keys : [] }; });
      const versionObj = objs.find(o => o.type === 'x-mitre-collection');
      return { framework: 'MITRE ATT&CK Enterprise', dataset_kind: 'stix-import', version: versionObj ? versionObj.x_mitre_version : (bundle.spec_version || 'unknown'), tactics, techniques, data_components, stats: { tactics: tactics.length, techniques: techniques.filter(t => !t.is_subtechnique).length, subtechniques: techniques.filter(t => t.is_subtechnique).length } };
    },
    // Validate an imported attack dataset (either STIX-converted or native Sentinel compact format)
    validateAttackDataset(ds) {
      const errors = [], warnings = [];
      if (!ds || !Array.isArray(ds.techniques) || !Array.isArray(ds.tactics)) { errors.push('Dataset must have techniques[] and tactics[]'); return { ok: false, errors, warnings }; }
      const ids = new Set();
      for (const t of ds.techniques) { if (!/^T\d{4}(\.\d{3})?$/.test(t.id || '')) errors.push('Invalid technique id: ' + t.id); if (ids.has(t.id)) warnings.push('Duplicate technique id ' + t.id); ids.add(t.id); if (!t.name) errors.push('Technique without name: ' + t.id); if (!Array.isArray(t.tactics) || !t.tactics.length) warnings.push(t.id + ' has no tactic'); }
      if (ds.tactics.length < 10) warnings.push('Only ' + ds.tactics.length + ' tactics present');
      return { ok: errors.length === 0, errors: errors.slice(0, 50), warnings: warnings.slice(0, 50) };
    },
    diffAgainstCurrent(ds) {
      const cur = new Map(FW.allTechniques().map(t => [t.id, t])); const nxt = new Map(ds.techniques.map(t => [t.id, t]));
      const added = [], removed = [], renamed = [];
      for (const [id, t] of nxt) { if (!cur.has(id)) added.push(id); else if (cur.get(id).name !== t.name) renamed.push({ id, from: cur.get(id).name, to: t.name }); }
      for (const id of cur.keys()) if (!nxt.has(id)) removed.push(id);
      return { added, removed, renamed, currentCount: cur.size, nextCount: nxt.size };
    },
    async applyAttackDataset(ds) { await FW.persistAttack(ds, { source: ds.dataset_kind || 'import' }); FW.attack = ds; FW.index(); SM.emit('frameworks:loaded'); }
  };
  SM.FW = FW;
})(globalThis.SM = globalThis.SM || {});
