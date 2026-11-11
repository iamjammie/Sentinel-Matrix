/* SENTINEL MATRIX — SVG chart primitives (no external libraries). */
(function (SM) {
  'use strict';
  const h = SM.h; const NS = 'http://www.w3.org/2000/svg';
  const C = { cyan: '#19d3f3', blue: '#3b82f6', violet: '#8b5cf6', amber: '#f5b942', red: '#f0506e', green: '#2fd48b', orange: '#fb8c3c', grey: '#4a5670' };
  const PALETTE = [C.cyan, C.blue, C.violet, C.green, C.amber, C.orange, C.red, '#6ee7d6', '#a78bfa', '#7dd3fc'];
  const COV_COLORS = { VALIDATED: C.green, FULLY_COVERED: C.cyan, PARTIALLY_COVERED: '#e5d04a', WEAK_COVERAGE: C.orange, UNVALIDATED_COVERAGE: C.orange, NOT_COVERED: C.red, NOT_APPLICABLE: C.grey, UNKNOWN: '#2a3449' };
  SM.CHART_COLORS = C; SM.COV_COLORS = COV_COLORS;
  const tip = (e, html) => SM.tooltip.show(e, html);

  function svg(w, hgt, cls) { const s = document.createElementNS(NS, 'svg'); s.setAttribute('viewBox', `0 0 ${w} ${hgt}`); s.setAttribute('preserveAspectRatio', 'xMidYMid meet'); if (cls) s.setAttribute('class', cls); s.setAttribute('width', '100%'); return s; }
  const el = (tag, attrs) => { const e = document.createElementNS(NS, tag); for (const k in attrs) if (attrs[k] !== undefined && attrs[k] !== null) e.setAttribute(k, attrs[k]); return e; };
  const txt = (x, y, s, attrs = {}) => { const t = el('text', Object.assign({ x, y }, attrs)); t.textContent = SM.str(s); return t; };

  // Horizontal bar chart (good for long category labels)
  SM.chartHBar = (data, { height, max, unit = '', color, onClick, fmt } = {}) => {
    data = data.filter(d => d); const W = 480, rowH = 26, padL = 150, padR = 54; const H = height || (data.length * rowH + 16);
    const s = svg(W, H, 'chart'); const mx = max || Math.max(1, ...data.map(d => d.value));
    data.forEach((d, i) => { const y = i * rowH + 8; const bw = (W - padL - padR) * (d.value / mx); const col = d.color || color || PALETTE[i % PALETTE.length];
      s.appendChild(txt(padL - 8, y + 13, SM.truncate(d.label, 22), { 'text-anchor': 'end', 'font-size': 11 }));
      const bar = el('rect', { x: padL, y: y + 3, width: Math.max(1, bw), height: rowH - 10, rx: 3, fill: col, class: 'bar', opacity: .88 }); bar.style.cursor = onClick ? 'pointer' : 'default';
      bar.addEventListener('mousemove', e => tip(e, h('div', null, h('strong', d.label), h('br'), (fmt ? fmt(d.value) : SM.fmtNum(d.value)) + ' ' + unit))); bar.addEventListener('mouseleave', () => SM.tooltip.hide()); if (onClick) bar.addEventListener('click', () => onClick(d));
      s.appendChild(bar); s.appendChild(txt(padL + bw + 6, y + 13, fmt ? fmt(d.value) : SM.fmtNum(d.value), { 'font-size': 11, fill: 'var(--text-1)' })); });
    return h('div', { class: 'chart' }, s);
  };
  // Vertical bars
  SM.chartVBar = (data, { height = 220, unit = '', color, onClick, stacked } = {}) => {
    const W = 480, padB = 46, padT = 14, padL = 40; const H = height; const s = svg(W, H, 'chart');
    const mx = Math.max(1, ...data.map(d => stacked ? SM.sum(d.segments, x => x.value) : d.value));
    const bw = (W - padL - 10) / data.length; const scale = (v) => (H - padB - padT) * (v / mx);
    for (let g = 0; g <= 4; g++) { const yy = padT + (H - padB - padT) * g / 4; s.appendChild(el('line', { x1: padL, y1: yy, x2: W - 6, y2: yy, stroke: 'var(--glass-border)', 'stroke-width': .5 })); s.appendChild(txt(padL - 5, yy + 3, Math.round(mx * (1 - g / 4)), { 'text-anchor': 'end', 'font-size': 9, fill: 'var(--text-3)' })); }
    data.forEach((d, i) => { const x = padL + i * bw + bw * 0.14; const w = bw * 0.72;
      if (stacked) { let acc = 0; (d.segments || []).forEach((seg, j) => { const sh = scale(seg.value); const yy = H - padB - acc - sh; acc += sh; const r = el('rect', { x, y: yy, width: w, height: Math.max(0, sh), fill: seg.color || PALETTE[j % PALETTE.length], class: 'bar' }); r.addEventListener('mousemove', e => tip(e, h('div', null, h('strong', d.label), h('br'), seg.label + ': ' + SM.fmtNum(seg.value)))); r.addEventListener('mouseleave', () => SM.tooltip.hide()); s.appendChild(r); }); }
      else { const bh = scale(d.value); const r = el('rect', { x, y: H - padB - bh, width: w, height: Math.max(0, bh), rx: 2, fill: d.color || color || C.cyan, class: 'bar' }); r.style.cursor = onClick ? 'pointer' : ''; r.addEventListener('mousemove', e => tip(e, h('div', null, h('strong', d.label), h('br'), SM.fmtNum(d.value) + ' ' + unit))); r.addEventListener('mouseleave', () => SM.tooltip.hide()); if (onClick) r.addEventListener('click', () => onClick(d)); s.appendChild(r); }
      const lbl = txt(x + w / 2, H - padB + 14, SM.truncate(d.label, 10), { 'text-anchor': 'middle', 'font-size': 9.5, fill: 'var(--text-2)' }); if (data.length > 10) lbl.setAttribute('transform', `rotate(40 ${x + w / 2} ${H - padB + 14})`), lbl.setAttribute('text-anchor', 'start'); s.appendChild(lbl); });
    return h('div', { class: 'chart' }, s);
  };
  // Donut
  SM.chartDonut = (data, { size = 180, unit = '', centerLabel, onClick } = {}) => {
    data = data.filter(d => d.value > 0); const total = SM.sum(data, d => d.value) || 1; const s = svg(size, size, 'chart'); const cx = size / 2, cy = size / 2, r = size / 2 - 6, ir = r * 0.62; let a0 = -Math.PI / 2;
    data.forEach((d, i) => { const frac = d.value / total; const a1 = a0 + frac * 2 * Math.PI; const large = frac > 0.5 ? 1 : 0; const p = (ang, rad) => [cx + rad * Math.cos(ang), cy + rad * Math.sin(ang)]; const [x0, y0] = p(a0, r), [x1, y1] = p(a1, r), [x2, y2] = p(a1, ir), [x3, y3] = p(a0, ir); const path = el('path', { d: `M${x0} ${y0} A${r} ${r} 0 ${large} 1 ${x1} ${y1} L${x2} ${y2} A${ir} ${ir} 0 ${large} 0 ${x3} ${y3} Z`, fill: d.color || PALETTE[i % PALETTE.length], opacity: .9 }); path.style.cursor = onClick ? 'pointer' : ''; path.addEventListener('mousemove', e => tip(e, h('div', null, h('strong', d.label), h('br'), SM.fmtNum(d.value) + ' ' + unit + ' (' + Math.round(frac * 100) + '%)'))); path.addEventListener('mouseleave', () => SM.tooltip.hide()); if (onClick) path.addEventListener('click', () => onClick(d)); s.appendChild(path); a0 = a1; });
    if (centerLabel !== undefined) { s.appendChild(txt(cx, cy - 2, centerLabel.big, { 'text-anchor': 'middle', 'font-size': 22, 'font-weight': 700, fill: 'var(--text-0)' })); if (centerLabel.small) s.appendChild(txt(cx, cy + 15, centerLabel.small, { 'text-anchor': 'middle', 'font-size': 10, fill: 'var(--text-2)' })); }
    return h('div', { class: 'chart' }, s);
  };
  // Multi-line
  SM.chartLine = (series, { height = 220, labels = [], unit = '' } = {}) => {
    const W = 480, padL = 40, padB = 28, padT = 10; const H = height; const s = svg(W, H, 'chart'); const n = Math.max(...series.map(se => se.points.length)); const mx = Math.max(1, ...series.flatMap(se => se.points)); const xs = (i) => padL + (W - padL - 10) * (n <= 1 ? 0.5 : i / (n - 1)); const ys = (v) => H - padB - (H - padB - padT) * (v / mx);
    for (let g = 0; g <= 4; g++) { const yy = padT + (H - padB - padT) * g / 4; s.appendChild(el('line', { x1: padL, y1: yy, x2: W - 6, y2: yy, stroke: 'var(--glass-border)', 'stroke-width': .5 })); s.appendChild(txt(padL - 5, yy + 3, Math.round(mx * (1 - g / 4)), { 'text-anchor': 'end', 'font-size': 9, fill: 'var(--text-3)' })); }
    series.forEach((se, i) => { const d = se.points.map((v, j) => (j ? 'L' : 'M') + xs(j) + ' ' + ys(v)).join(' '); s.appendChild(el('path', { d, fill: 'none', stroke: se.color || PALETTE[i % PALETTE.length], 'stroke-width': 2 })); se.points.forEach((v, j) => { const c = el('circle', { cx: xs(j), cy: ys(v), r: 2.5, fill: se.color || PALETTE[i % PALETTE.length] }); c.addEventListener('mousemove', e => tip(e, h('div', null, h('strong', se.label), h('br'), (labels[j] || j) + ': ' + SM.fmtNum(v) + ' ' + unit))); c.addEventListener('mouseleave', () => SM.tooltip.hide()); s.appendChild(c); }); });
    (labels || []).forEach((l, j) => { if (labels.length > 12 && j % 2) return; s.appendChild(txt(xs(j), H - padB + 14, SM.truncate(l, 8), { 'text-anchor': 'middle', 'font-size': 9, fill: 'var(--text-3)' })); });
    return h('div', { class: 'chart' }, s);
  };
  // Score ring (0-100)
  SM.scoreRing = (score, { size = 90, label, color } = {}) => {
    const s = svg(size, size); const r = size / 2 - 7, cx = size / 2; const circ = 2 * Math.PI * r; const col = color || (score >= 70 ? C.green : score >= 45 ? C.amber : C.red);
    s.appendChild(el('circle', { cx, cy: cx, r, fill: 'none', stroke: 'var(--bg-3)', 'stroke-width': 7 }));
    s.appendChild(el('circle', { cx, cy: cx, r, fill: 'none', stroke: col, 'stroke-width': 7, 'stroke-linecap': 'round', 'stroke-dasharray': circ, 'stroke-dashoffset': circ * (1 - SM.clamp(score, 0, 100) / 100), transform: `rotate(-90 ${cx} ${cx})` }));
    s.appendChild(txt(cx, cx + 1, score, { 'text-anchor': 'middle', 'dominant-baseline': 'middle', 'font-size': 20, 'font-weight': 700, fill: 'var(--text-0)' }));
    if (label) s.appendChild(txt(cx, cx + 16, label, { 'text-anchor': 'middle', 'font-size': 8.5, fill: 'var(--text-2)' }));
    return h('div', { class: 'chart', style: { maxWidth: size + 'px' } }, s);
  };
  SM.legend = (items) => h('div', { class: 'legend' }, items.map(it => h('span', null, h('span', { class: 'cov-swatch', style: { background: it.color } }), it.label + (it.value !== undefined ? ' (' + it.value + ')' : ''))));
})(globalThis.SM = globalThis.SM || {});
