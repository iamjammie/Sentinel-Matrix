/* SENTINEL MATRIX — virtualised table (handles 10k+ rows, renders only visible slice). */
(function (SM) {
  'use strict';
  const h = SM.h;
  // columns: [{key,label,width,render?(row)->Node/string, sort?(a,b), align}]
  SM.VTable = function VTable(columns, options = {}) {
    const rowH = options.rowH || 34; const self = {};
    let rows = []; let sorted = []; let sortKey = options.sortKey || null; let sortDir = options.sortDir || 1; let selectedId = null;
    const idOf = options.idKey ? (r => r[options.idKey]) : (r => r._i);
    const grid = columns.map(c => c.width || '1fr').join(' ');
    const wrap = h('div', { class: 'vtable' });
    const thead = h('div', { class: 'thead', style: { gridTemplateColumns: grid } });
    const body = h('div', { class: 'body', style: { maxHeight: (options.maxHeight || 520) + 'px' } });
    const spacer = h('div', { class: 'spacer' });
    const foot = h('div', { class: 'tfoot' });
    body.appendChild(spacer); wrap.append(thead, body, foot);
    columns.forEach(c => { const th = h('div', { class: 'th', style: { textAlign: c.align || 'left' } }, c.label, sortKey === c.key ? h('span', { class: 'arrow' }, sortDir > 0 ? '▲' : '▼') : null); if (c.sortable !== false) th.addEventListener('click', () => { if (sortKey === c.key) sortDir = -sortDir; else { sortKey = c.key; sortDir = 1; } applySort(); renderHead(); render(); }); thead.appendChild(th); });
    function renderHead() { SM.$$('.th', thead).forEach((th, i) => { const a = SM.$('.arrow', th); if (a) a.remove(); if (columns[i].key === sortKey) th.appendChild(h('span', { class: 'arrow' }, sortDir > 0 ? '▲' : '▼')); }); }
    function applySort() { sorted = rows.slice(); if (sortKey) { const col = columns.find(c => c.key === sortKey); sorted.sort((a, b) => { if (col && col.sort) return col.sort(a, b) * sortDir; let va = a[sortKey], vb = b[sortKey]; if (Array.isArray(va)) va = va.length; if (Array.isArray(vb)) vb = vb.length; if (va == null) va = ''; if (vb == null) vb = ''; if (typeof va === 'number' && typeof vb === 'number') return (va - vb) * sortDir; return SM.str(va).localeCompare(SM.str(vb), undefined, { numeric: true }) * sortDir; }); } }
    let scrollRAF = null; body.addEventListener('scroll', () => { if (scrollRAF) return; scrollRAF = requestAnimationFrame(() => { scrollRAF = null; render(); }); });
    const pool = [];
    function render() {
      const scrollTop = body.scrollTop; const viewH = body.clientHeight || options.maxHeight || 520; const total = sorted.length;
      spacer.style.height = (total * rowH) + 'px';
      const start = Math.max(0, Math.floor(scrollTop / rowH) - 6); const end = Math.min(total, Math.ceil((scrollTop + viewH) / rowH) + 6);
      const need = end - start; while (pool.length < need) { const tr = h('div', { class: 'tr', style: { gridTemplateColumns: grid, height: rowH + 'px' } }); columns.forEach(() => tr.appendChild(h('div', { class: 'td' }))); body.appendChild(tr); pool.push(tr); }
      for (let i = 0; i < pool.length; i++) { const tr = pool[i]; const idx = start + i; if (idx >= end) { tr.style.display = 'none'; continue; } tr.style.display = 'grid'; const row = sorted[idx]; tr.style.transform = `translateY(${idx * rowH}px)`; tr.classList.toggle('selected', selectedId !== null && idOf(row) === selectedId);
        const tds = tr.children; columns.forEach((c, ci) => { const td = tds[ci]; SM.clear(td); td.style.textAlign = c.align || 'left'; const v = c.render ? c.render(row) : row[c.key]; if (v instanceof Node) td.appendChild(v); else td.textContent = SM.str(v); });
        tr.onclick = () => { if (options.onRow) { selectedId = idOf(row); options.onRow(row); render(); } };
      }
      foot.textContent = SM.fmtNum(total) + (total === 1 ? ' row' : ' rows') + (self._filteredFrom ? ' (filtered from ' + SM.fmtNum(self._filteredFrom) + ')' : '');
      if (options.footExtra) { const ex = options.footExtra(sorted); SM.clear(foot); foot.append(h('span', SM.fmtNum(total) + ' rows'), ex); }
    }
    self.el = wrap;
    self.setRows = (data, filteredFrom) => { rows = data.map((r, i) => (r._i = i, r)); self._filteredFrom = filteredFrom; applySort(); body.scrollTop = 0; render(); return self; };
    self.getSorted = () => sorted; self.refresh = () => { applySort(); render(); }; self.select = (id) => { selectedId = id; render(); };
    return self;
  };
})(globalThis.SM = globalThis.SM || {});
