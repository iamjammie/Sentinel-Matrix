#!/usr/bin/env node
/* SENTINEL MATRIX — headless browser smoke + acceptance test via Playwright. */
const { chromium } = require('playwright');
const path = require('path');
const fs = require('fs');
const FILE = 'file://' + path.join(__dirname, '..', '..', 'dist', 'sentinel-matrix.html');

(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage();
  const errors = [];
  page.on('console', m => { if (m.type() === 'error') errors.push(m.text()); });
  page.on('pageerror', e => errors.push('PAGEERROR: ' + e.message));
  let pass = 0, fail = 0; const fails = [];
  const ok = (n, c, d) => { if (c) pass++; else { fail++; fails.push(n + (d ? ' — ' + d : '')); console.log('  ✗ ' + n + (d ? ' — ' + d : '')); } };

  await page.goto(FILE, { waitUntil: 'networkidle' });
  await page.waitForFunction(() => window.SM && window.SM.FW && window.SM.FW.loaded, { timeout: 15000 });
  await page.waitForSelector('#sidebar .nav-item', { timeout: 10000 });

  console.log('Boot');
  ok('App shell rendered (17 nav items)', (await page.$$('#sidebar .nav-item')).length === 17, '' + (await page.$$('#sidebar .nav-item')).length);
  ok('No console/page errors on boot', errors.length === 0, errors.slice(0, 3).join(' | '));
  ok('Splash removed', !(await page.$('#splash')));
  ok('IndexedDB mode (not memory) in Chromium', await page.evaluate(() => !SM.DB.memMode()));

  // Acceptance Test 1 — import 1000 rules
  console.log('AT1 — import 1000 rules');
  const t1 = Date.now();
  await page.evaluate(async () => {
    const rules = [];
    for (let i = 0; i < 1000; i++) rules.push({ rule_id: 'imp-' + i, rule_name: 'Rule ' + i, severity: ['high', 'medium', 'low'][i % 3], enabled: i % 5 !== 0, technique: i % 2 ? 'T1558.003' : 'T1059.001', query: 'EventCode=' + (4624 + (i % 10)) + ' | stats count by user', description: i % 3 ? 'desc' : '' });
    // duplicates: make 50 identical logic
    for (let i = 0; i < 50; i++) rules.push({ rule_id: 'dup-' + i, rule_name: 'Dup Rule', technique: 'T1110.003', query: 'IDENTICAL LOGIC BLOCK', enabled: true, severity: 'high' });
    const parsed = SM.Import.adapters.generic.parse(rules, { format: 'json', platform: 'generic' });
    const q = SM.Import.analyseBatch(parsed, SM.Store.rules);
    window.__at1 = { parsed: parsed.length, dupes: q.duplicates, unmapped: q.missing_mapping };
    const batch = 'at1'; await SM.Store.addRules(parsed, batch);
  });
  const at1 = await page.evaluate(() => window.__at1);
  ok('AT1 parsed 1050 rules', at1.parsed === 1050, '' + at1.parsed);
  ok('AT1 identified duplicates', at1.dupes >= 49, 'dupes=' + at1.dupes);
  ok('AT1 stored in DB', await page.evaluate(() => SM.Store.rules.length) === 1050);
  ok('AT1 preserved original content', await page.evaluate(() => SM.Store.rules[0].original_rule_content !== null));
  ok('AT1 completed quickly', Date.now() - t1 < 8000, (Date.now() - t1) + 'ms');

  // AT2 — coverage assessment
  console.log('AT2 — coverage assessment');
  await page.evaluate(async () => { await SM.runCoverage(); });
  const at2 = await page.evaluate(() => ({ results: SM.Store.coverage.results.length, composite: SM.Store.coverage.summary.composite, uncovered: SM.Store.coverage.summary.counts.NOT_COVERED, na: SM.Store.coverage.summary.counts.NOT_APPLICABLE, dims: Object.keys(SM.Store.coverage.summary.dimensions).length }));
  ok('AT2 coverage for all techniques', at2.results > 400);
  ok('AT2 composite computed', at2.composite >= 0 && at2.composite <= 100, '' + at2.composite);
  ok('AT2 identifies uncovered', at2.uncovered > 0);
  ok('AT2 six dimensions', at2.dims === 6);

  // navigate to matrix and check cells render
  await page.evaluate(() => SM.App.go('matrix'));
  await page.waitForSelector('.tech-cell', { timeout: 5000 });
  ok('AT2 matrix renders cells', (await page.$$('.tech-cell')).length > 50);

  // AT3 — gap analysis
  console.log('AT3 — gap analysis');
  await page.evaluate(async () => { await SM.runGaps(); });
  const at3 = await page.evaluate(() => ({ gaps: SM.Store.gaps.length, hasRec: SM.Store.gaps[0] && SM.Store.gaps[0].recommended_action.length > 0, intelUnknown: SM.Store.gaps.every(g => g.threat_relevance_known === false) }));
  ok('AT3 gaps generated', at3.gaps > 0, '' + at3.gaps);
  ok('AT3 gaps have recommendations', at3.hasRec);
  ok('AT3 threat relevance unknown without intel', at3.intelUnknown);

  // AT4 — rule generation for QRadar
  console.log('AT4 — rule generation (QRadar)');
  const at4 = await page.evaluate(() => { const r = SM.Generator.generateForTechnique('T1558.003', { platform: 'qradar' }); return { count: r.scenarios.length, distinct: new Set(r.scenarios.map(s => s.objective)).size, hasTests: r.scenarios.every(s => s.test_cases.length >= 0), isSpec: r.scenarios[0].rendered_body.includes('RULE SPECIFICATION'), hasTuning: r.scenarios[0].tuning.length > 0, hasTelemetry: r.scenarios[0].required_telemetry.length > 0 }; });
  ok('AT4 multiple scenarios', at4.count >= 6, '' + at4.count);
  ok('AT4 scenarios distinct', at4.distinct === at4.count);
  ok('AT4 QRadar output is specification', at4.isSpec);
  ok('AT4 includes tuning + telemetry', at4.hasTuning && at4.hasTelemetry);

  // AT7 — persistence across reload
  console.log('AT7 — data integrity across reload');
  await page.reload({ waitUntil: 'networkidle' });
  await page.waitForFunction(() => window.SM && window.SM.Store && window.SM.Store.rules !== undefined, { timeout: 15000 });
  await page.waitForFunction(() => window.SM.FW.loaded, { timeout: 10000 });
  const at7 = await page.evaluate(() => ({ rules: SM.Store.rules.length, cov: !!SM.Store.coverage, gaps: SM.Store.gaps.length }));
  ok('AT7 rules persisted', at7.rules === 1050, '' + at7.rules);
  ok('AT7 coverage persisted', at7.cov);
  ok('AT7 gaps persisted', at7.gaps > 0);

  // AT8 — security checks
  console.log('AT8 — security');
  const html = fs.readFileSync(path.join(__dirname, '..', '..', 'dist', 'sentinel-matrix.html'), 'utf8');
  ok('AT8 no eval()', !/[^.\w]eval\s*\(/.test(html.replace(/\/\*[\s\S]*?\*\//g, '')));
  ok('AT8 no new Function', !/new\s+Function\s*\(/.test(html));
  ok('AT8 no external script src', !/<script[^>]+src=/.test(html));
  ok('AT8 no http(s) CDN links in markup', !/(src|href)=["']https?:\/\//.test(html.replace(/\bhttps?:\/\/www\.w3\.org[^"']*/g, '')));
  ok('AT8 no credentials persisted', !/localStorage\.setItem\([^)]*token/i.test(html));

  // AT9 — 10k rule stress + virtualization
  console.log('AT9 — 10k rule stress');
  const t9 = Date.now();
  await page.evaluate(async () => { const rules = []; for (let i = 0; i < 10000; i++) rules.push({ rule_id: 'stress-' + i, rule_name: 'Stress ' + i, technique: 'T' + (1000 + (i % 600)), query: 'q' + i, enabled: true, severity: 'medium' }); const parsed = SM.Import.adapters.generic.parse(rules, { format: 'json', platform: 'generic' }); await SM.Store.addRules(parsed, 'stress'); });
  ok('AT9 loaded 10k+ rules', await page.evaluate(() => SM.Store.rules.length) >= 11000);
  await page.evaluate(() => SM.App.go('inventory'));
  await page.waitForSelector('.vtable .tr', { timeout: 8000 });
  const domRows = await page.evaluate(() => document.querySelectorAll('.vtable .body .tr').length);
  ok('AT9 virtualised (renders < 60 DOM rows, not all)', domRows < 60 && domRows > 0, domRows + ' DOM rows');
  ok('AT9 stress completed in time', Date.now() - t9 < 30000, (Date.now() - t9) + 'ms');

  // visual: capture a dashboard screenshot
  await page.evaluate(() => SM.App.go('command'));
  await page.waitForSelector('.kpi-card', { timeout: 5000 });
  await page.screenshot({ path: path.join(__dirname, '..', '..', 'dist', 'dashboard-screenshot.png') });
  ok('Dashboard renders KPI cards', (await page.$$('.kpi-card')).length > 10);
  ok('No errors during full run', errors.length === 0, errors.slice(0, 3).join(' | '));

  console.log('\nRESULT: ' + pass + ' passed, ' + fail + ' failed');
  if (fail) console.log('Failures:\n' + fails.map(f => '  - ' + f).join('\n'));
  await browser.close();
  process.exit(fail ? 1 : 0);
})().catch(e => { console.error('BROWSER TEST ERROR', e); process.exit(2); });
