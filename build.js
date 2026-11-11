#!/usr/bin/env node
/* SENTINEL MATRIX — build script. Assembles the modular source into a single offline sentinel-matrix.html.
   No external build tooling; pure Node fs. */
const fs = require('fs');
const path = require('path');
const ROOT = __dirname;
const SRC = path.join(ROOT, 'src');
const DATA = path.join(ROOT, 'data');
const DIST = path.join(ROOT, 'dist');

const JS_ORDER = [
  '00_core.js', '01_db.js', '02_frameworks.js', '03_import.js', '04_coverage.js', '05_scenarios.js',
  '06_generator.js', '07_gaps_quality.js', '08_search_state.js', '10_charts.js', '11_vtable.js',
  '20_app.js', '21_mod_inventory.js', '22_mod_command.js', '23_mod_coverage_matrix.js', '24_mod_gaps.js',
  '25_mod_generator.js', '26_mod_validation_lifecycle.js', '27_mod_liveaudit.js', '28_mod_offenses_logs.js',
  '29_mod_chain_assets.js', '30_mod_reports_framework_settings.js', '40_demo.js', '99_boot.js'
];
const DATA_MAP = {
  __DATA_ATTACK__: 'attack-enterprise.json', __DATA_D3FEND__: 'd3fend.json', __DATA_CAPEC__: 'capec.json',
  __DATA_KILLCHAIN__: 'killchain.json', __DATA_TELEMETRY__: 'telemetry-map.json', __DATA_EVENTIDS__: 'event-ids.json',
  __DATA_LOGSOURCES__: 'log-source-catalog.json', __DATA_PROFILES__: 'environment-profiles.json',
  __DATA_SCENARIOS__: 'detection-scenario-templates.json', __DATA_SIGMA__: 'sigma-sample-pack.json'
};
const LOGO = '<svg viewBox="0 0 48 48"><defs><linearGradient id="slg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#19d3f3"/><stop offset="1" stop-color="#8b5cf6"/></linearGradient></defs><path d="M24 3l17 6v11c0 11-7 20-17 24C14 40 7 31 7 20V9z" fill="none" stroke="url(#slg)" stroke-width="2.4"/><path d="M24 14v20M15 24h18M18 18l12 12M30 18L18 30" stroke="#19d3f3" stroke-width="1.6" stroke-linecap="round" opacity="0.85"/><circle cx="24" cy="24" r="3.4" fill="#19d3f3"/></svg>';

function readJSONMin(file) { const raw = fs.readFileSync(path.join(DATA, file), 'utf8'); return JSON.stringify(JSON.parse(raw)); }
function sanitizeForScriptTag(s) { return s.replace(/<\/(script)/gi, '<\\/$1').replace(/<!--/g, '<\\!--'); }

function build() {
  if (!fs.existsSync(DIST)) fs.mkdirSync(DIST, { recursive: true });
  // syntax-check every module before assembling
  const vm = require('vm');
  for (const f of JS_ORDER) { const src = fs.readFileSync(path.join(SRC, 'js', f), 'utf8'); try { new vm.Script(src, { filename: f }); } catch (e) { throw new Error('Syntax error in ' + f + ': ' + e.message); } }
  const css = fs.readFileSync(path.join(SRC, 'css', 'app.css'), 'utf8');
  let js = JS_ORDER.map(f => '/* ===== ' + f + ' ===== */\n' + fs.readFileSync(path.join(SRC, 'js', f), 'utf8')).join('\n');
  const buildDate = new Date().toISOString().slice(0, 10);
  js = js.replace('__BUILD_DATE__', buildDate);
  let html = fs.readFileSync(path.join(SRC, 'index.template.html'), 'utf8');
  html = html.replace('/*__CSS__*/', () => css);
  html = html.replace('/*__JS__*/', () => sanitizeForScriptTag(js));
  html = html.replace(/__LOGO__/g, () => LOGO);
  let totalData = 0;
  for (const [token, file] of Object.entries(DATA_MAP)) { const json = sanitizeForScriptTag(readJSONMin(file)); totalData += json.length; html = html.replace(token, () => json); }
  // verify no tokens remain
  const leftover = html.match(/__DATA_[A-Z]+__|__CSS__|__JS__/g);
  if (leftover) throw new Error('Unreplaced build tokens: ' + leftover.join(', '));
  const outPath = path.join(DIST, 'sentinel-matrix.html');
  fs.writeFileSync(outPath, html);
  const kb = (n) => (n / 1024).toFixed(1) + ' KB';
  console.log('Built ' + outPath);
  console.log('  CSS:   ' + kb(css.length));
  console.log('  JS:    ' + kb(js.length) + ' (' + JS_ORDER.length + ' modules)');
  console.log('  Data:  ' + kb(totalData) + ' (10 bundled datasets)');
  console.log('  Total: ' + kb(html.length));
  // also copy standalone data packages to dist/data-packages for separate distribution
  const pkgDir = path.join(DIST, 'data-packages'); if (!fs.existsSync(pkgDir)) fs.mkdirSync(pkgDir, { recursive: true });
  for (const file of Object.values(DATA_MAP)) fs.copyFileSync(path.join(DATA, file), path.join(pkgDir, file));
  console.log('  Data packages copied to dist/data-packages/');
  return outPath;
}
if (require.main === module) { try { build(); } catch (e) { console.error('BUILD FAILED:', e.message); process.exit(1); } }
module.exports = { build };
