#!/usr/bin/env node
/* SENTINEL MATRIX — Node engine tests. Loads the pure-logic modules (no DOM) and exercises
   import, coverage, gaps, quality, generator against the real bundled datasets. */
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..', '..');
const SRC = path.join(ROOT, 'src', 'js');
const DATA = path.join(ROOT, 'data');

// Minimal sandbox: provide globalThis with SM, console, a stub document/DOMParser not needed for engine modules.
const sandbox = { console, Date, Math, JSON, RegExp, Array, Object, String, Number, Set, Map, Promise, setTimeout, isNaN, parseInt, parseFloat, globalThis: {} };
sandbox.globalThis = sandbox;
sandbox.navigator = undefined; sandbox.indexedDB = undefined; sandbox.document = undefined;
vm.createContext(sandbox);

const ENGINE_MODULES = ['00_core.js', '01_db.js', '02_frameworks.js', '03_import.js', '04_coverage.js', '05_scenarios.js', '06_generator.js', '07_gaps_quality.js'];
for (const m of ENGINE_MODULES) vm.runInContext(fs.readFileSync(path.join(SRC, m), 'utf8'), sandbox, { filename: m });
const SM = sandbox.SM;

// inject bundled datasets
SM.BUNDLED = {
  attack: JSON.parse(fs.readFileSync(path.join(DATA, 'attack-enterprise.json'), 'utf8')),
  d3fend: JSON.parse(fs.readFileSync(path.join(DATA, 'd3fend.json'), 'utf8')),
  capec: JSON.parse(fs.readFileSync(path.join(DATA, 'capec.json'), 'utf8')),
  killchain: JSON.parse(fs.readFileSync(path.join(DATA, 'killchain.json'), 'utf8')),
  telemetry: JSON.parse(fs.readFileSync(path.join(DATA, 'telemetry-map.json'), 'utf8')),
  eventids: JSON.parse(fs.readFileSync(path.join(DATA, 'event-ids.json'), 'utf8')),
  logsources: JSON.parse(fs.readFileSync(path.join(DATA, 'log-source-catalog.json'), 'utf8')),
  profiles: JSON.parse(fs.readFileSync(path.join(DATA, 'environment-profiles.json'), 'utf8')),
  scenarios: JSON.parse(fs.readFileSync(path.join(DATA, 'detection-scenario-templates.json'), 'utf8')),
  sigma: JSON.parse(fs.readFileSync(path.join(DATA, 'sigma-sample-pack.json'), 'utf8'))
};

let pass = 0, fail = 0; const fails = [];
function ok(name, cond, detail) { if (cond) { pass++; } else { fail++; fails.push(name + (detail ? ' — ' + detail : '')); console.log('  ✗ ' + name + (detail ? ' — ' + detail : '')); } }
function section(s) { console.log('\n' + s); }

(async () => {
  // DB in memory mode
  await SM.DB.ready();
  ok('DB is in memory mode under Node', SM.DB.memMode() === true);

  // Frameworks
  await SM.FW.init();
  section('Framework datasets');
  ok('ATT&CK techniques loaded', SM.FW.allTechniques().length > 400, SM.FW.allTechniques().length + ' techniques');
  ok('14 tactics', SM.FW.tacticsOrdered().length === 14);
  ok('Technique lookup works', SM.FW.technique('T1558.003') && SM.FW.technique('T1558.003').name === 'Kerberoasting');
  ok('Telemetry resolves for T1558.003', SM.FW.telemetryFor('T1558.003').logSourceTypes.includes('active_directory'));
  ok('D3FEND mapping for T1003', SM.FW.d3fendFor('T1003.001').length > 0);
  ok('CAPEC mapping for T1558.003', SM.FW.capecFor('T1558.003').length > 0);
  await SM.Scenarios.init();
  ok('Scenario KB loaded', SM.Scenarios.count() > 40, SM.Scenarios.count() + ' scenarios');
  ok('Kerberoasting has 8 scenarios', SM.Scenarios.get('T1558.003').scenarios.length === 8);

  // Import adapters
  section('Import & normalisation');
  const sigmaYaml = fs.readFileSync(path.join(__dirname, 'fixtures', 'sample.sigma.yml'), 'utf8');
  const docs = SM.parseYAML(sigmaYaml);
  ok('YAML parses Sigma doc', docs.length === 1 && docs[0].title, JSON.stringify(docs[0] && docs[0].title));
  const sigmaRules = SM.Import.adapters.sigma.parse(docs, { format: 'yaml' });
  ok('Sigma adapter yields a rule', sigmaRules.length === 1 && !sigmaRules[0].error);
  ok('Sigma rule maps T1558.003 explicitly', sigmaRules[0].attack_techniques.includes('T1558.003') && sigmaRules[0].mapping_source.startsWith('explicit'), sigmaRules[0].mapping_source);
  ok('Sigma log source inferred', sigmaRules[0].log_source_types.includes('windows_security') || sigmaRules[0].log_source_types.includes('active_directory'), sigmaRules[0].log_source_types.join(','));

  const elasticJson = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'sample.elastic.json'), 'utf8'));
  ok('Elastic auto-detected', SM.Import.adapters.elastic.detect(elasticJson));
  const elasticRules = SM.Import.adapters.elastic.parse(elasticJson, { format: 'json' });
  ok('Elastic rule parsed with technique', elasticRules[0].attack_techniques.includes('T1059.001'), elasticRules[0].attack_techniques.join(','));

  const qradarJson = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'sample.qradar.json'), 'utf8'));
  ok('QRadar auto-detected', SM.Import.adapters.qradar.detect(qradarJson));
  const qradarRules = SM.Import.adapters.qradar.parse(qradarJson, { format: 'json' });
  ok('QRadar rule parsed', qradarRules[0].rule_name && qradarRules[0].source_platform === 'qradar');

  const csv = 'rule_id,rule_name,severity,enabled,technique,query\nR1,Test Rule,high,true,T1110.003,EventCode=4625 | stats count by src\nR1,Test Rule,high,true,T1110.003,EventCode=4625 | stats count by src';
  const csvParsed = SM.parseCSV(csv);
  ok('CSV parses 2 records', csvParsed.records.length === 2);
  const csvRules = SM.Import.adapters.csv.parse(csvParsed, { format: 'csv' });
  ok('CSV rule mapped', csvRules[0].attack_techniques.includes('T1110.003'));
  const batchAnalysis = SM.Import.analyseBatch(csvRules, []);
  ok('Duplicate detection finds 1 dup', batchAnalysis.duplicates === 1, 'dups=' + batchAnalysis.duplicates);

  // inferred-only mapping flagged
  const inferRule = SM.Import.adapters.generic.parse([{ name: 'Mimikatz LSASS dump detection', query: 'x', enabled: true, severity: 'high' }], { format: 'json', platform: 'generic' })[0];
  ok('Keyword-inferred mapping marked inferred', inferRule.mapping_source === 'inferred' && inferRule.inferred_techniques.includes('T1003.001'), inferRule.mapping_source + ' ' + inferRule.attack_techniques);

  // XXE protection
  let xxeBlocked = false; try { SM.parseXML('<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "b">]><r/>'); } catch (e) { xxeBlocked = true; }
  ok('XML with DOCTYPE/ENTITY rejected (XXE protection)', xxeBlocked);
  // prototype pollution
  const pp = SM.safeJSON('{"__proto__":{"polluted":true},"a":1}');
  ok('Prototype pollution key stripped', pp.a === 1 && ({}).polluted === undefined);

  // Build a rule corpus and store
  section('Coverage engine');
  const rules = []; const scn = SM.Scenarios.all();
  for (const st of scn) for (const sc of st.scenarios) { const r = SM.Import.blank(); r.source_platform = 'qradar'; r.rule_name = sc.name; r.detection_logic = JSON.stringify(sc.selection); r.enabled_status = 'enabled'; r.severity = sc.severity; r.log_source_types = sc.log_source_types.slice(); r.event_ids = sc.event_ids.slice(); SM.Import.applyMappings(r, [st.technique], [], sc.name + ' ' + st.technique); SM.Import.finalise(r, {}); rules.push(r); }
  const logSources = (SM.FW.profile('ad_enterprise').expected_log_sources).map(t => ({ id: 'ls-' + t, source_type: t, zone: 'Server LAN', health_status: 'healthy', collection_status: 'active' }));
  const cov = SM.Coverage.assess({ rules, techniques: SM.FW.allTechniques(), logSources, tests: [], profile: SM.FW.profile('ad_enterprise'), assets: [], scenarioKB: SM.Scenarios.forCoverage(), telemetryFor: id => SM.FW.telemetryFor(id), alertStats: {} });
  ok('Coverage produced results for all techniques', cov.results.length === SM.FW.allTechniques().length);
  const krb = cov.results.find(r => r.technique_id === 'T1558.003');
  ok('Kerberoasting assessed as covered (telemetry+scenarios present)', ['FULLY_COVERED', 'PARTIALLY_COVERED'].includes(krb.classification), krb.classification);
  const uncovered = cov.results.find(r => r.classification === 'NOT_COVERED');
  ok('Some techniques are NOT_COVERED', !!uncovered);
  ok('NOT_APPLICABLE used for off-platform techniques', cov.results.some(r => r.classification === 'NOT_APPLICABLE'));
  ok('Composite score is 0-100', cov.summary.composite >= 0 && cov.summary.composite <= 100, '' + cov.summary.composite);
  ok('Six dimensions present', Object.keys(cov.summary.dimensions).length === 6);

  // telemetry-less coverage → unvalidated/weak
  const covNoTel = SM.Coverage.assess({ rules, techniques: SM.FW.allTechniques(), logSources: [], tests: [], profile: SM.FW.profile('ad_enterprise'), scenarioKB: SM.Scenarios.forCoverage(), telemetryFor: id => SM.FW.telemetryFor(id) });
  ok('Without telemetry inventory, telemetry_known=false', covNoTel.telemetry_known === false);
  const krbNoTel = covNoTel.results.find(r => r.technique_id === 'T1558.003');
  ok('Without telemetry, not marked FULLY_COVERED', krbNoTel.classification !== 'FULLY_COVERED', krbNoTel.classification);

  // disabled rule → weak
  const disabledRules = rules.map(r => Object.assign({}, r, { enabled_status: 'disabled' }));
  const covDisabled = SM.Coverage.assess({ rules: disabledRules, techniques: SM.FW.allTechniques(), logSources, profile: SM.FW.profile('ad_enterprise'), scenarioKB: SM.Scenarios.forCoverage(), telemetryFor: id => SM.FW.telemetryFor(id) });
  ok('All-disabled rules yield WEAK_COVERAGE', covDisabled.results.find(r => r.technique_id === 'T1558.003').classification === 'WEAK_COVERAGE');

  // validated
  const tests = [{ rule_id: rules.find(r => r.attack_techniques.includes('T1558.003')).rule_id, status: 'PASS' }];
  const covVal = SM.Coverage.assess({ rules, techniques: SM.FW.allTechniques(), logSources, tests, profile: SM.FW.profile('ad_enterprise'), scenarioKB: SM.Scenarios.forCoverage(), telemetryFor: id => SM.FW.telemetryFor(id) });
  ok('Passed test yields VALIDATED', covVal.results.find(r => r.technique_id === 'T1558.003').classification === 'VALIDATED');

  // Gaps
  section('Gap analysis');
  const gaps = SM.Gaps.analyse(cov.results, { assets: [], telemetry: SM.Coverage.availableTelemetry(logSources), intel: null, telemetryFor: id => SM.FW.telemetryFor(id) });
  ok('Gaps generated for uncovered techniques', gaps.gaps.length > 0, gaps.gaps.length + ' gaps');
  ok('Gaps sorted by priority desc', gaps.gaps.every((g, i) => i === 0 || gaps.gaps[i - 1].priority_score >= g.priority_score));
  ok('Threat relevance marked unknown without intel', gaps.gaps.every(g => g.threat_relevance_known === false));
  ok('Priority scores 0-100', gaps.gaps.every(g => g.priority_score >= 0 && g.priority_score <= 100));
  const withIntel = SM.Gaps.analyse(cov.results, { assets: [], telemetry: SM.Coverage.availableTelemetry(logSources), intel: { 'T1486': 95 }, telemetryFor: id => SM.FW.telemetryFor(id) });
  ok('Intel flips threat_relevance_known for mapped technique', withIntel.gaps.some(g => g.technique_id === 'T1486' && g.threat_relevance_known === true) || !withIntel.gaps.some(g => g.technique_id === 'T1486'));

  // Quality
  section('Rule quality');
  const q = SM.Quality.assess(rules[0], { telemetry: SM.Coverage.availableTelemetry(logSources), alertStats: {}, testsByRule: {} });
  ok('Quality score 0-100 with grade', q.score >= 0 && q.score <= 100 && /[A-E]/.test(q.grade));
  const enabledThin = SM.Import.blank(); enabledThin.enabled_status = 'enabled'; enabledThin.rule_name = 'x'; enabledThin.detection_logic = 'x'; SM.Import.finalise(enabledThin, {});
  const qThin = SM.Quality.assess(enabledThin, { telemetry: SM.Coverage.availableTelemetry([]) });
  ok('Enabled-but-empty rule does NOT get high score', qThin.score < 50, '' + qThin.score);
  // never-triggered not auto-ineffective
  const eff = SM.Quality.effectiveness(Object.assign({}, rules[0], { enabled_status: 'enabled' }), { alertStats: { [rules[0].rule_id]: { alerts: 0, observation_days: 30 } }, telemetry: SM.Coverage.availableTelemetry(logSources) });
  ok('Never-triggered flagged as info (not ineffective)', eff.flags.every(f => f.sev !== 'high' || f.k !== 'never_triggered'));

  // Generator
  section('Rule generator');
  const gen = SM.Generator.generateForTechnique('T1558.003', { platform: 'sigma' });
  ok('Generates 8 distinct scenarios', gen.scenarios.length === 8);
  ok('Scenarios have distinct objectives', new Set(gen.scenarios.map(s => s.objective)).size === 8);
  ok('Each has test cases', gen.scenarios.every(s => Array.isArray(s.test_cases)));
  ok('Sigma output present', gen.scenarios[0].rendered_body.includes('title:'));
  const splunk = SM.Generator.render(gen.scenarios[0].spec, 'splunk');
  ok('SPL output present', /search|stats/.test(splunk.body));
  const kql = SM.Generator.render(gen.scenarios[0].spec, 'sentinel');
  ok('KQL output present', /where|summarize|SecurityEvent/.test(kql.body));
  const qr = SM.Generator.render(gen.scenarios[0].spec, 'qradar');
  ok('QRadar output is a specification (not fake CRE)', qr.body.includes('RULE SPECIFICATION') && qr.body.includes('not QRadar CRE syntax'));
  ok('Generated rule maturity labelled', gen.scenarios[0].maturity === 'generated_specification');

  // Validation evaluation logic
  section('Validation evaluation');
  // emulate the evalSpec used in UI by re-testing scenario test cases against their own spec is UI-only; here we at least check selections exist
  ok('Kerberoasting KRB-01 has match + no_match tests', (() => { const s = SM.Scenarios.get('T1558.003').scenarios.find(x => x.id === 'KRB-01'); return s.tests.some(t => t.expected === 'match') && s.tests.some(t => t.expected === 'no_match'); })());

  // STIX parse (tiny synthetic bundle)
  section('STIX import');
  const stix = { type: 'bundle', objects: [
    { type: 'x-mitre-tactic', x_mitre_shortname: 'execution', name: 'Execution', description: 'x', external_references: [{ source_name: 'mitre-attack', external_id: 'TA0002' }] },
    { type: 'attack-pattern', name: 'Fake Technique', x_mitre_platforms: ['Windows'], kill_chain_phases: [{ kill_chain_name: 'mitre-attack', phase_name: 'execution' }], external_references: [{ source_name: 'mitre-attack', external_id: 'T9999' }] }
  ] };
  const ds = SM.FW.parseStix(stix);
  ok('STIX parse yields technique T9999', ds.techniques.some(t => t.id === 'T9999'));
  const val = SM.FW.validateAttackDataset(ds);
  ok('STIX dataset validates (with warnings)', val.ok === true);

  // backup round-trip
  section('Persistence / backup');
  await SM.DB.bulkPut('rules', rules);
  const exp = await SM.DB.exportWorkspace({ includeFrameworks: false });
  ok('Export has integrity checksum', !!exp.integrity);
  ok('Export excludes framework stores when asked', !exp.stores.attack_techniques);
  const rep = await SM.DB.importWorkspace(exp, { merge: false });
  ok('Import round-trips rules', rep.rules === rules.length, 'imported ' + rep.rules);

  section('RESULT');
  console.log('  ' + pass + ' passed, ' + fail + ' failed');
  if (fail) { console.log('\nFailures:\n' + fails.map(f => '  - ' + f).join('\n')); process.exit(1); }
  console.log('  ALL ENGINE TESTS PASSED');
})().catch(e => { console.error('TEST HARNESS ERROR', e); process.exit(2); });
