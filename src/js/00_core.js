/* SENTINEL MATRIX — core utilities, DOM helpers, safe parsers, event bus.
   All modules attach to the SM namespace. No eval, no Function(), no innerHTML with data. */
(function (SM) {
  'use strict';
  SM.VERSION = '1.0.0';
  SM.BUILD_DATE = '__BUILD_DATE__';
  SM.APP_NAME = 'SENTINEL MATRIX';
  SM.TAGLINE = 'See the Gaps. Engineer the Defence. Detect the Adversary.';

  // ---------- Event bus ----------
  const listeners = new Map();
  SM.on = (evt, fn) => { if (!listeners.has(evt)) listeners.set(evt, new Set()); listeners.get(evt).add(fn); return () => listeners.get(evt).delete(fn); };
  SM.emit = (evt, payload) => { (listeners.get(evt) || []).forEach(fn => { try { fn(payload); } catch (e) { console.error('listener error', evt, e); } }); };

  // ---------- IDs / time ----------
  SM.uid = (prefix = 'id') => prefix + '_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 9);
  SM.now = () => new Date().toISOString();
  SM.fmtDate = (iso) => { if (!iso) return '—'; const d = new Date(iso); return isNaN(d) ? String(iso) : d.toISOString().replace('T', ' ').slice(0, 16) + 'Z'; };
  SM.fmtNum = (n) => (n === null || n === undefined || isNaN(n)) ? '—' : Number(n).toLocaleString('en-GB');
  SM.pct = (a, b) => b ? Math.round((a / b) * 1000) / 10 : 0;
  SM.clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

  // ---------- Text helpers ----------
  SM.str = (v) => (v === null || v === undefined) ? '' : (typeof v === 'string' ? v : (typeof v === 'object' ? JSON.stringify(v) : String(v)));
  SM.truncate = (s, n = 80) => { s = SM.str(s); return s.length > n ? s.slice(0, n - 1) + '…' : s; };
  SM.slug = (s) => SM.str(s).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  SM.uniq = (arr) => Array.from(new Set((arr || []).filter(x => x !== undefined && x !== null && x !== '')));
  SM.asArray = (v) => v === undefined || v === null ? [] : (Array.isArray(v) ? v : [v]);
  SM.groupBy = (arr, fn) => { const m = new Map(); for (const x of arr) { const k = typeof fn === 'function' ? fn(x) : x[fn]; if (!m.has(k)) m.set(k, []); m.get(k).push(x); } return m; };
  SM.countBy = (arr, fn) => { const m = {}; for (const x of arr) { const k = typeof fn === 'function' ? fn(x) : x[fn]; m[k] = (m[k] || 0) + 1; } return m; };
  SM.sum = (arr, fn) => arr.reduce((a, x) => a + (fn ? fn(x) : x), 0);
  SM.deepClone = (o) => JSON.parse(JSON.stringify(o));
  SM.hash = (s) => { // FNV-1a 32-bit, for duplicate detection fingerprints
    s = SM.str(s); let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return (h >>> 0).toString(16).padStart(8, '0');
  };
  SM.normaliseLogic = (s) => SM.str(s).toLowerCase().replace(/\s+/g, ' ').replace(/['"`]/g, '').trim();

  // ATT&CK ID extraction — strict pattern so random text does not become a mapping
  SM.TECH_RE = /\bT\d{4}(?:\.\d{3})?\b/g;
  SM.extractTechniqueIds = (text) => SM.uniq((SM.str(text).match(SM.TECH_RE) || []).map(x => x.toUpperCase()));
  SM.parentTechnique = (id) => SM.str(id).split('.')[0];

  // ---------- Safe parsing ----------
  SM.safeJSON = (text, { maxBytes = 300 * 1024 * 1024 } = {}) => {
    if (typeof text !== 'string') throw new Error('JSON input must be text');
    if (text.length > maxBytes) throw new Error('JSON input exceeds size limit');
    const t = text.replace(/^﻿/, '');
    // reject prototype pollution keys
    const parsed = JSON.parse(t, (k, v) => (k === '__proto__' || k === 'constructor' || k === 'prototype') ? undefined : v);
    return parsed;
  };

  // Minimal RFC4180-ish CSV parser with quoted fields and embedded newlines
  SM.parseCSV = (text, delimiter) => {
    text = SM.str(text).replace(/^﻿/, '');
    if (!delimiter) { const first = text.split(/\r?\n/)[0] || ''; delimiter = (first.split('\t').length > first.split(',').length) ? '\t' : (first.split(';').length > first.split(',').length ? ';' : ','); }
    const rows = []; let row = [], field = '', q = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
      else if (c === '"') q = true;
      else if (c === delimiter) { row.push(field); field = ''; }
      else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
      else if (c === '\r') { /* skip */ }
      else field += c;
    }
    if (field.length || row.length) { row.push(field); rows.push(row); }
    if (!rows.length) return { headers: [], records: [] };
    const headers = rows[0].map(h => h.trim());
    const records = rows.slice(1).filter(r => r.some(x => x.trim() !== '')).map(r => { const o = {}; headers.forEach((h, i) => o[h] = r[i] === undefined ? '' : r[i]); return o; });
    return { headers, records, delimiter };
  };
  SM.toCSV = (rows, headers) => {
    if (!rows.length) return '';
    headers = headers || SM.uniq(rows.flatMap(r => Object.keys(r)));
    const esc = (v) => { const s = Array.isArray(v) ? v.join('|') : SM.str(v); return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s; };
    return [headers.join(','), ...rows.map(r => headers.map(h => esc(r[h])).join(','))].join('\r\n');
  };

  // Secure XML parse: DOMParser does not expand external entities; we additionally reject DOCTYPE declarations (XXE/billion-laughs surface)
  SM.parseXML = (text) => {
    text = SM.str(text).replace(/^﻿/, '');
    if (/<!DOCTYPE/i.test(text) || /<!ENTITY/i.test(text)) throw new Error('XML documents containing DOCTYPE/ENTITY declarations are rejected for security reasons');
    if (typeof DOMParser === 'undefined') throw new Error('XML parsing requires a browser DOMParser');
    const doc = new DOMParser().parseFromString(text, 'application/xml');
    const err = doc.getElementsByTagName('parsererror')[0];
    if (err) throw new Error('XML parse error: ' + (err.textContent || '').slice(0, 200));
    return doc;
  };
  SM.xmlToObject = (node) => { // generic element → plain object conversion
    const obj = {};
    if (node.attributes) for (const a of node.attributes) obj['@' + a.name] = a.value;
    const kids = Array.from(node.children || []);
    if (!kids.length) { const t = (node.textContent || '').trim(); return Object.keys(obj).length ? Object.assign(obj, { '#text': t }) : t; }
    for (const k of kids) { const v = SM.xmlToObject(k); if (obj[k.tagName] === undefined) obj[k.tagName] = v; else { if (!Array.isArray(obj[k.tagName])) obj[k.tagName] = [obj[k.tagName]]; obj[k.tagName].push(v); } }
    return obj;
  };

  // Compact YAML subset parser sufficient for Sigma rules (maps, sequences, scalars, block scalars, inline lists). No anchors/tags executed.
  SM.parseYAML = (text) => {
    const lines = SM.str(text).replace(/\r/g, '').split('\n').map(l => l.replace(/\t/g, '  '));
    const docs = []; let cur = [];
    for (const l of lines) { if (/^---\s*$/.test(l)) { if (cur.length) docs.push(cur); cur = []; } else if (/^\.\.\.\s*$/.test(l)) { /* end */ } else cur.push(l); }
    if (cur.length) docs.push(cur);
    const parseScalar = (s) => {
      s = s.trim();
      if (s === '' || s === '~' || s === 'null') return null;
      if (s === 'true') return true; if (s === 'false') return false;
      if (/^-?\d+$/.test(s)) return parseInt(s, 10);
      if (/^-?\d*\.\d+$/.test(s)) return parseFloat(s);
      if ((s.startsWith("'") && s.endsWith("'"))) return s.slice(1, -1).replace(/''/g, "'");
      if ((s.startsWith('"') && s.endsWith('"'))) { try { return JSON.parse(s); } catch (e) { return s.slice(1, -1); } }
      if (s.startsWith('[') && s.endsWith(']')) return splitInline(s.slice(1, -1)).map(parseScalar);
      if (s.startsWith('{') && s.endsWith('}')) { const o = {}; splitInline(s.slice(1, -1)).forEach(p => { const i = p.indexOf(':'); if (i > 0) o[p.slice(0, i).trim()] = parseScalar(p.slice(i + 1)); }); return o; }
      return s;
    };
    const splitInline = (s) => { const out = []; let d = 0, q = null, cur = ''; for (const c of s) { if (q) { cur += c; if (c === q) q = null; continue; } if (c === '"' || c === "'") { q = c; cur += c; continue; } if (c === '[' || c === '{') d++; if (c === ']' || c === '}') d--; if (c === ',' && d === 0) { out.push(cur); cur = ''; } else cur += c; } if (cur.trim()) out.push(cur); return out; };
    const stripComment = (l) => { let q = null, out = ''; for (let i = 0; i < l.length; i++) { const c = l[i]; if (q) { out += c; if (c === q) q = null; continue; } if (c === '"' || c === "'") { q = c; out += c; continue; } if (c === '#' && (i === 0 || /\s/.test(l[i - 1]))) break; out += c; } return out; };
    const indentOf = (l) => l.match(/^ */)[0].length;
    function parseBlock(ls, i, indent) {
      // returns [value, nextIndex]
      while (i < ls.length && stripComment(ls[i]).trim() === '') i++;
      if (i >= ls.length) return [null, i];
      const first = stripComment(ls[i]);
      const ind = indentOf(first);
      if (ind < indent) return [null, i];
      if (first.trim().startsWith('- ') || first.trim() === '-') {
        const arr = [];
        while (i < ls.length) {
          const raw = stripComment(ls[i]); if (raw.trim() === '') { i++; continue; }
          if (indentOf(raw) !== ind || !(raw.trim().startsWith('- ') || raw.trim() === '-')) break;
          const rest = raw.trim().slice(1).trim();
          if (rest === '') { const [v, ni] = parseBlock(ls, i + 1, ind + 1); arr.push(v); i = ni; }
          else if (/^[^'"\[{][^:]*:(\s|$)/.test(rest) && !rest.startsWith('http')) {
            // inline mapping start inside a sequence item: rewrite the line as indented map
            const sub = [' '.repeat(ind + 2) + rest]; let j = i + 1;
            while (j < ls.length) { const r = stripComment(ls[j]); if (r.trim() === '') { sub.push(''); j++; continue; } if (indentOf(r) > ind) { sub.push(r); j++; } else break; }
            const [v] = parseBlock(sub, 0, ind + 2); arr.push(v); i = j;
          } else { arr.push(parseScalar(rest)); i++; }
        }
        return [arr, i];
      }
      const obj = {};
      while (i < ls.length) {
        const raw = stripComment(ls[i]); if (raw.trim() === '') { i++; continue; }
        if (indentOf(raw) < ind) break;
        if (indentOf(raw) > ind) { i++; continue; }
        const m = raw.trim().match(/^((?:"[^"]*")|(?:'[^']*')|[^:]+?)\s*:(?:\s+(.*))?$/);
        if (!m) { i++; continue; }
        let key = m[1].trim(); if (/^["']/.test(key)) key = key.slice(1, -1);
        const val = m[2];
        if (val === undefined || val.trim() === '') { const [v, ni] = parseBlock(ls, i + 1, ind + 1); obj[key] = v; i = ni; }
        else if (val.trim() === '|' || val.trim() === '>' || val.trim() === '|-' || val.trim() === '>-') {
          const fold = val.trim().startsWith('>'); const buf = []; let j = i + 1; let bi = null;
          while (j < ls.length) { const r = ls[j]; if (r.trim() === '') { buf.push(''); j++; continue; } const bind = indentOf(r); if (bi === null) bi = bind; if (bind < bi || bind <= ind) break; buf.push(r.slice(bi)); j++; }
          while (buf.length && buf[buf.length - 1] === '') buf.pop();
          obj[key] = fold ? buf.join(' ').replace(/\s+/g, ' ') : buf.join('\n'); i = j;
        } else { obj[key] = parseScalar(val); i++; }
      }
      return [obj, i];
    }
    return docs.map(d => parseBlock(d, 0, 0)[0]).filter(x => x !== null);
  };
  SM.toYAML = (obj, indent = 0) => {
    const pad = ' '.repeat(indent);
    const q = (s) => { s = SM.str(s); return /^[\w./-][\w ./:()\-,*]*$/.test(s) && !/^(true|false|null|~|\d+)$/.test(s) ? s : JSON.stringify(s); };
    if (Array.isArray(obj)) return obj.map(v => (v && typeof v === 'object') ? pad + '-\n' + SM.toYAML(v, indent + 2).replace(new RegExp('^' + pad + '  ', ''), pad + '  ') : pad + '- ' + q(v)).join('\n');
    if (obj && typeof obj === 'object') return Object.entries(obj).map(([k, v]) => {
      if (v && typeof v === 'object') { const inner = SM.toYAML(v, indent + 2); return pad + k + ':' + (Array.isArray(v) && !v.length ? ' []' : '\n' + inner); }
      if (typeof v === 'string' && v.includes('\n')) return pad + k + ': |\n' + v.split('\n').map(l => pad + '  ' + l).join('\n');
      return pad + k + ': ' + q(v);
    }).join('\n');
    return pad + q(obj);
  };

  // ---------- DOM helpers (text-only insertion; attributes whitelisted) ----------
  const SAFE_ATTR = /^(class|id|type|value|placeholder|title|href|target|rel|for|name|min|max|step|rows|cols|disabled|checked|selected|multiple|accept|download|role|tabindex|aria-[a-z-]+|data-[a-z0-9-]+|colspan|rowspan|width|height|viewBox|d|fill|stroke|stroke-width|x|y|x1|x2|y1|y2|cx|cy|r|rx|ry|points|transform|text-anchor|dominant-baseline|font-size|opacity|stroke-dasharray|stroke-dashoffset|stroke-linecap|fill-opacity|xmlns|preserveAspectRatio|font-weight|style|readonly|autocomplete|spellcheck|draggable)$/;
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const SVG_TAGS = new Set(['svg', 'g', 'rect', 'circle', 'path', 'line', 'text', 'polyline', 'polygon', 'defs', 'linearGradient', 'stop', 'tspan', 'title']);
  SM.h = function h(tag, attrs, ...children) {
    const isSvg = SVG_TAGS.has(tag);
    const el = isSvg ? document.createElementNS(SVG_NS, tag) : document.createElement(tag);
    if (attrs && typeof attrs === 'object' && !(attrs instanceof Node) && !Array.isArray(attrs)) {
      for (const [k, v] of Object.entries(attrs)) {
        if (v === null || v === undefined || v === false) continue;
        if (k.startsWith('on') && typeof v === 'function') { el.addEventListener(k.slice(2).toLowerCase(), v); continue; }
        if (k === 'style' && typeof v === 'object') { Object.assign(el.style, v); continue; }
        if (k === 'dataset' && typeof v === 'object') { for (const [dk, dv] of Object.entries(v)) el.dataset[dk] = SM.str(dv); continue; }
        if (k === 'text') { el.textContent = SM.str(v); continue; }
        if (k === 'href' && /^\s*javascript:/i.test(SM.str(v))) continue;
        if (!SAFE_ATTR.test(k)) continue;
        if (v === true) el.setAttribute(k, ''); else el.setAttribute(k, SM.str(v));
      }
    } else if (attrs !== undefined && attrs !== null) children.unshift(attrs);
    SM.append(el, children);
    return el;
  };
  SM.append = (el, children) => { for (const c of children.flat(Infinity)) { if (c === null || c === undefined || c === false) continue; el.appendChild(c instanceof Node ? c : document.createTextNode(SM.str(c))); } return el; };
  SM.clear = (el) => { while (el.firstChild) el.removeChild(el.firstChild); return el; };
  SM.$ = (sel, root = document) => root.querySelector(sel);
  SM.$$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));
  SM.sanitizeText = (s) => SM.str(s).replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F]/g, '');

  // ---------- Download / file helpers ----------
  SM.download = (filename, content, mime = 'application/octet-stream') => {
    const blob = content instanceof Blob ? content : new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = SM.h('a', { href: url, download: filename }); document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1500);
  };
  SM.readFileText = (file) => new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(r.result); r.onerror = () => rej(r.error); r.readAsText(file); });
  SM.detectFormat = (name, text) => {
    const ext = (name || '').toLowerCase().split('.').pop();
    const head = SM.str(text).slice(0, 4000).trimStart();
    if (ext === 'yml' || ext === 'yaml') return 'yaml';
    if (ext === 'xml' || head.startsWith('<?xml') || head.startsWith('<')) return 'xml';
    if (ext === 'json' || ext === 'ndjson' || head.startsWith('{') || head.startsWith('[')) return head.includes('\n{') && !head.startsWith('[') && !head.startsWith('{\n') ? 'ndjson' : 'json';
    if (ext === 'csv' || ext === 'tsv') return 'csv';
    if (/^\s*title:\s/m.test(head) && /detection:/.test(head)) return 'yaml';
    if (/^\s*\[.*\]\s*$/m.test(head) && /search\s*=/.test(head)) return 'splunk-conf';
    return 'unknown';
  };

  // ---------- Toasts / modal / drawer / tooltip ----------
  SM.toast = (msg, kind = 'info', ms = 4200) => {
    const box = SM.$('#toasts'); if (!box) { console.log('[toast]', kind, msg); return; }
    const t = SM.h('div', { class: 'toast ' + kind }, msg); box.appendChild(t);
    setTimeout(() => { t.style.opacity = '0'; setTimeout(() => t.remove(), 300); }, ms);
    SM.notify && SM.notify(msg, kind);
  };
  SM.notifications = [];
  SM.notify = (msg, kind = 'info') => { SM.notifications.unshift({ id: SM.uid('n'), msg, kind, at: SM.now(), read: false }); if (SM.notifications.length > 100) SM.notifications.length = 100; SM.emit('notifications'); };

  SM.modal = ({ title, body, footer, wide, onClose }) => {
    const back = SM.$('#modal-back'); const m = SM.$('#modal'); SM.clear(m); m.className = 'modal' + (wide ? ' wide' : '');
    const close = () => { back.classList.remove('open'); SM.clear(m); onClose && onClose(); };
    m.appendChild(SM.h('div', { class: 'modal-head' }, SM.h('h2', title), SM.h('button', { class: 'icon-btn', onClick: close, 'aria-label': 'Close' }, '✕')));
    m.appendChild(SM.h('div', { class: 'modal-body' }, body));
    if (footer) m.appendChild(SM.h('div', { class: 'modal-foot' }, footer(close)));
    back.classList.add('open');
    back.onclick = (e) => { if (e.target === back) close(); };
    return { close };
  };
  SM.confirm = (title, text, { danger = false, okLabel = 'Confirm' } = {}) => new Promise((res) => {
    SM.modal({ title, body: SM.h('p', text), footer: (close) => [SM.h('button', { class: 'btn', onClick: () => { close(); res(false); } }, 'Cancel'), SM.h('button', { class: 'btn ' + (danger ? 'danger' : 'primary'), onClick: () => { close(); res(true); } }, okLabel)], onClose: () => res(false) });
  });
  SM.prompt = (title, label, def = '') => new Promise((res) => {
    const inp = SM.h('input', { type: 'text', value: def });
    SM.modal({ title, body: SM.h('div', { class: 'field' }, SM.h('label', label), inp), footer: (close) => [SM.h('button', { class: 'btn', onClick: () => { close(); res(null); } }, 'Cancel'), SM.h('button', { class: 'btn primary', onClick: () => { close(); res(inp.value); } }, 'OK')], onClose: () => res(null) });
    setTimeout(() => inp.focus(), 50);
  });
  SM.drawer = {
    open(title, body, sub) { const d = SM.$('#drawer'); SM.clear(d);
      d.appendChild(SM.h('div', { class: 'drawer-head' }, SM.h('div', null, SM.h('h2', title), sub ? SM.h('div', { class: 'muted small' }, sub) : null), SM.h('button', { class: 'icon-btn', onClick: () => SM.drawer.close(), 'aria-label': 'Close' }, '✕')));
      d.appendChild(SM.h('div', { class: 'drawer-body' }, body)); d.classList.add('open'); },
    close() { SM.$('#drawer').classList.remove('open'); }
  };
  SM.tooltip = {
    show(e, content) { let t = SM.$('#tooltip'); if (!t) { t = SM.h('div', { id: 'tooltip', class: 'tooltip' }); document.body.appendChild(t); } SM.clear(t); SM.append(t, [content]); t.style.display = 'block'; SM.tooltip.move(e); },
    move(e) { const t = SM.$('#tooltip'); if (!t) return; const x = Math.min(e.clientX + 12, window.innerWidth - 330), y = Math.min(e.clientY + 12, window.innerHeight - 100); t.style.left = x + 'px'; t.style.top = y + 'px'; },
    hide() { const t = SM.$('#tooltip'); if (t) t.style.display = 'none'; }
  };

  // ---------- Simple tabs ----------
  SM.tabs = (defs, { active = 0, onChange } = {}) => {
    const wrap = SM.h('div'); const bar = SM.h('div', { class: 'tabs' }); const body = SM.h('div');
    const btns = defs.map((d, i) => SM.h('div', { class: 'tab' + (i === active ? ' active' : ''), onClick: () => show(i) }, d.label));
    function show(i) { btns.forEach((b, j) => b.classList.toggle('active', i === j)); SM.clear(body); const r = defs[i].render(); SM.append(body, [r]); onChange && onChange(i); }
    SM.append(bar, btns); wrap.append(bar, body); show(active); return wrap;
  };

  // ---------- Coverage constants ----------
  SM.COVERAGE = {
    VALIDATED: { label: 'Validated', color: 'var(--cov-validated)', rank: 6, desc: 'At least one enabled, telemetry-backed rule has passed an executed validation test for this technique.' },
    FULLY_COVERED: { label: 'Fully covered (operational)', color: 'var(--cov-operational)', rank: 5, desc: 'Enabled rule(s) with required telemetry available and acceptable logic quality, covering the main detection scenarios. Not yet validated by test execution.' },
    PARTIALLY_COVERED: { label: 'Partially covered', color: 'var(--cov-partial)', rank: 4, desc: 'Enabled rule(s) exist but cover only a subset of detection scenarios, or telemetry is only partially available.' },
    WEAK_COVERAGE: { label: 'Weak coverage', color: 'var(--cov-weak)', rank: 3, desc: 'Rules exist but are disabled, lack telemetry, have low logic quality, or are only inferred mappings.' },
    UNVALIDATED_COVERAGE: { label: 'Unvalidated', color: 'var(--cov-weak)', rank: 3, desc: 'Rules are mapped and enabled but telemetry availability could not be determined.' },
    NOT_COVERED: { label: 'Not covered', color: 'var(--cov-none)', rank: 1, desc: 'No rule maps to this technique or any of its sub-techniques.' },
    NOT_APPLICABLE: { label: 'Not applicable', color: 'var(--cov-na)', rank: 0, desc: 'Technique does not apply to the platforms in the active environment profile.' },
    UNKNOWN: { label: 'Unknown / not assessed', color: 'var(--cov-unknown)', rank: 2, desc: 'Not assessed yet. Run the coverage analysis.' }
  };
  SM.SEVERITIES = ['critical', 'high', 'medium', 'low', 'informational'];
  SM.normSeverity = (s) => { s = SM.str(s).toLowerCase().trim(); if (!s) return 'unknown'; if (/^(crit|critical|5|very high|fatal)/.test(s)) return 'critical'; if (/^(high|4|major)/.test(s)) return 'high'; if (/^(med|medium|3|moderate)/.test(s)) return 'medium'; if (/^(low|2|minor)/.test(s)) return 'low'; if (/^(info|informational|1|0|none|verbose)/.test(s)) return 'informational'; const n = parseInt(s, 10); if (!isNaN(n)) return n >= 90 ? 'critical' : n >= 70 ? 'high' : n >= 40 ? 'medium' : n >= 15 ? 'low' : 'informational'; return 'unknown'; };
  SM.riskFromSeverity = (sev) => ({ critical: 95, high: 75, medium: 50, low: 25, informational: 10 }[sev] || 40);

})(globalThis.SM = globalThis.SM || {});
