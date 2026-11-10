/* 事件告警 */
(function () {
  'use strict';
  const { D, ic, $$, fmt, esc, fmtTime, relTime, avatar, countUp, toast, card, sevBadge, actBadge, stBadge, chIcon, pagerHtml, openLayer, confirmDialog, act, SEV, ACT, ST } = UI;
  const cache = new Map(); // 列表页加载过的事件（可能早于引导数据中的最近 600 条）

  /* ---------- 事件详情抽屉（总览页与事件页共用） ---------- */
  async function openIncident(id, onChange) {
    let i = D.incidents.find(x => x.id === id) || cache.get(id);
    if (!i) { try { i = await API.get('/incidents/' + encodeURIComponent(id)); } catch (e) { UI.apiError(e); return; } }
    if (!i) { toast('事件不存在或已被归档', { type: 'warning' }); return; }
    const dt = D.dtMap[i.dataType], ch = D.chMap[i.channel];
    const closedSt = i.status === 'resolved' || i.status === 'fp';
    const tl = [
      ['检测到外发', `${i.host} 通过${ch.name}外发至「${i.dest}」，识别到${dt.name} ${i.matches} 处`, i.ts, 'done'],
      ['策略处置', `命中「${i.policy || '未命中策略'}」${i.policyId ? '（' + i.policyId + '）' : ''}，${ACT[i.action] ? ACT[i.action].name : i.action}`, i.ts, 'done'],
      closedSt ? [i.status === 'fp' ? '标记为误报' : '已处置', i.handler ? `处置人：${i.handler}` : '', i.closed || null, 'done'] : ['等待处置', '可在下方确认处置或标记误报', null, 'current']
    ];
    const kv = [['用户', i.user], ['部门', i.dept || '-'], ['终端', i.host], ['IP 地址', i.ip || '-'], ['外发通道', ch.name], ['目的地', i.dest], ['数据类型', dt.name], ['命中数', String(i.matches)], ['文件大小', i.size || '-'], ['检测时间', fmtTime(i.ts)]];
    const html = `
      <div class="dr-head">
        <div class="dr-meta">${sevBadge(i.severity)}<span class="mono muted">${i.id}</span>${stBadge(i.status)}</div>
        <h2>${esc(i.file)}</h2><p>${esc(i.user)} · ${i.dept} · ${relTime(i.ts)}</p>
        <button class="icon-btn dr-close" data-close aria-label="关闭">${ic('x')}</button>
      </div>
      <div class="dr-body">
        <div class="callout c-${i.severity}">${ic('shield')}<div>${i.policy ? `该事件由策略 <b>「${esc(i.policy)}」</b> 触发，` : ''}处置动作：<b>${ACT[i.action] ? ACT[i.action].name : esc(i.action)}</b>。${i.severity === 'critical' ? '严重事件，建议优先处置。' : ''}</div></div>
        <h4 class="sec-t">AI 研判</h4>
        <div class="ai-box" id="aiBox"></div>
        <div class="kv">${kv.map(([k, v]) => `<div><span>${k}</span><b title="${esc(v)}">${esc(v)}</b></div>`).join('')}</div>
        <h4 class="sec-t">处置记录</h4>
        <ol class="timeline">${tl.map((t, k) => `<li class="${t[3]}" style="--i:${k}"><i></i><div><b>${t[0]}</b><p>${esc(t[1])}</p>${t[2] ? `<time>${fmtTime(t[2])}</time>` : ''}</div></li>`).join('')}</ol>
      </div>
      <div class="dr-foot">
        <button class="btn" data-a="fp" data-perm="incidents:op" ${closedSt ? 'disabled' : ''}>${ic('x')}标记误报</button>
        <button class="btn btn-primary" data-a="resolve" data-perm="incidents:op" ${closedSt ? 'disabled' : ''}>${ic('check')}确认处置</button>
      </div>`;
    const { panel, close } = openLayer('drawer', html);
    if (UI.ai) UI.ai.mountTriage(panel.querySelector('#aiBox'), i);
    panel.querySelector('.dr-foot').addEventListener('click', e => {
      const b = e.target.closest('[data-a]');
      if (!b || b.disabled) return;
      const a = b.dataset.a;
      const status = a === 'fp' ? 'fp' : 'resolved';
      act(b, () => API.post(`/incidents/${encodeURIComponent(i.id)}/resolve`, { status }), upd => {
        Object.assign(i, upd);
        const local = D.incidents.find(x => x.id === i.id); if (local && local !== i) Object.assign(local, upd);
        close();
        toast(status === 'fp' ? `事件 ${i.id} 已标记为误报` : `事件 ${i.id} 已确认处置`, { type: 'success', title: '处置成功' });
        UI.updateNav();
        onChange && onChange();
      });
    });
    UI.applyPerms(panel);
  }
  UI.openIncident = openIncident;

  const SEV_IC = { critical: 'zap', high: 'alert', medium: 'eye', low: 'shield' };

  UI.pages.incidents = {
    title: '事件告警', icon: 'alert',
    html() {
      return `
      <div class="page-head">
        <div><h1>事件告警</h1><p>集中查看、研判与处置数据外发风险事件</p></div>
        <div class="head-actions">
          <button class="btn" data-act="export" data-perm="incidents:exp">${ic('download')}导出</button>
          <button class="btn btn-primary" data-act="batch" data-perm="incidents:op" disabled>${ic('check')}批量处置<span class="cnt"></span></button>
        </div>
      </div>
      <div class="sev-cards">${Object.keys(SEV).map(s => `
        <button class="sev-card" data-sev="${s}" style="--c:var(--sev-${s})">
          <span class="sev-card-ic">${ic(SEV_IC[s])}</span>
          <div><span>${SEV[s].name}事件</span><b data-cnt="${s}">0</b></div>
          <small>待处置 <em data-pend="${s}">0</em></small>
        </button>`).join('')}</div>
      ${card('事件列表', `
        <div class="toolbar">
          <div class="search-box">${ic('search')}<input class="input" id="q" placeholder="搜索事件 ID、用户、文件名、终端…"></div>
          <select class="input" id="fch" aria-label="外发通道"><option value="all">全部通道</option>${D.channels.map(c => `<option value="${c.key}">${c.name}</option>`).join('')}</select>
          <select class="input" id="fst" aria-label="处置状态"><option value="all">全部状态</option>${Object.entries(ST).map(([k, v]) => `<option value="${k}">${v}</option>`).join('')}</select>
          <span class="sp"></span>
          <button class="btn btn-ghost btn-sm" id="reset">${ic('refresh')}重置筛选</button>
        </div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th class="ck"><input type="checkbox" id="ckAll" aria-label="全选"></th><th>事件 ID</th><th>级别</th><th>用户 / 部门</th><th>外发通道</th><th>敏感数据</th><th>文件</th><th>处置动作</th><th>状态</th><th>检测时间</th><th></th></tr></thead>
          <tbody id="rows"></tbody>
        </table></div>
        <div class="pager" id="pager"></div>`, { sub: '点击行查看事件详情与处置时间线', extra: '<span class="muted small" id="resCnt"></span>' })}`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      const f = { q: '', sev: UI.params.get('sev') || 'all', ch: 'all', st: UI.params.get('st') || 'all' };
      const per = 10; let page = 1, seq = 0, rows = [];
      const sel = new Set();
      const tbody = q('#rows'), batchBtn = q('[data-act="batch"]');
      const canOp = UI.canDo('incidents', 'op');
      q('#fst').value = f.st;

      const row = (i, idx) => `<tr class="clickable ${sel.has(i.id) ? 'selected' : ''}" data-id="${i.id}" style="--i:${idx}">
        <td class="ck"><input type="checkbox" data-ck ${sel.has(i.id) ? 'checked' : ''} ${canOp ? '' : 'disabled'} aria-label="选择 ${i.id}"></td>
        <td class="mono">${i.id}</td><td>${sevBadge(i.severity)}</td>
        <td><div class="u-cell">${avatar(i.user, 'sm')}<div><b>${esc(i.user)}</b><small>${esc(i.dept || '')}</small></div></div></td>
        <td>${chIcon(i.channel)}</td>
        <td><div class="dt-cell">${D.dtMap[i.dataType] ? D.dtMap[i.dataType].name : esc(i.dataType)}<small>命中 ${i.matches} 处</small></div></td>
        <td><div class="file-cell" title="${esc(i.file)}">${ic('file')}<span>${esc(i.file)}</span></div></td>
        <td>${actBadge(i.action)}</td><td>${stBadge(i.status)}</td>
        <td class="muted">${fmtTime(i.ts)}</td>
        <td><span class="row-go">${ic('chevron-right')}</span></td></tr>`;

      function syncChecks() {
        const ids = rows.map(r => r.id), ck = q('#ckAll');
        ck.checked = ids.length > 0 && ids.every(id => sel.has(id));
        ck.indeterminate = !ck.checked && ids.some(id => sel.has(id));
        batchBtn.disabled = sel.size === 0 || !canOp;
        batchBtn.querySelector('.cnt').textContent = sel.size || '';
      }
      async function render() {
        const my = ++seq;
        let r;
        try { r = await API.get('/incidents' + API.qs({ q: f.q, sev: f.sev, ch: f.ch, st: f.st, page, per })); } catch (e) { UI.apiError(e); return; }
        if (my !== seq || !root.isConnected) return; // 丢弃过期响应
        const pages = Math.max(1, Math.ceil(r.total / per));
        if (page > pages) { page = pages; return render(); }
        rows = r.items; rows.forEach(i => cache.set(i.id, i));
        tbody.innerHTML = rows.length ? rows.map(row).join('')
          : `<tr><td colspan="11"><div class="empty-st">${ic('file-search')}<p>没有符合条件的事件</p></div></td></tr>`;
        q('#resCnt').textContent = `筛选结果 ${fmt(r.total)} 条`;
        q('#pager').innerHTML = UI.pagerHtml(page, pages, r.total, per);
        Object.keys(SEV).forEach(s2 => {
          countUp(q(`[data-cnt="${s2}"]`), r.counts[s2].total);
          q(`[data-pend="${s2}"]`).textContent = r.counts[s2].pending;
        });
        $$('.sev-card', root).forEach(c => c.classList.toggle('on', c.dataset.sev === f.sev));
        syncChecks();
      }

      tbody.addEventListener('click', e => {
        const tr = e.target.closest('tr[data-id]'); if (!tr) return;
        if (e.target.closest('[data-ck]')) {
          const id = tr.dataset.id;
          sel.has(id) ? sel.delete(id) : sel.add(id);
          tr.classList.toggle('selected', sel.has(id));
          syncChecks();
          return;
        }
        openIncident(tr.dataset.id, render);
      });
      q('#ckAll').addEventListener('change', e => {
        if (!canOp) return;
        $$('tr[data-id]', tbody).forEach(tr => {
          e.target.checked ? sel.add(tr.dataset.id) : sel.delete(tr.dataset.id);
          tr.classList.toggle('selected', e.target.checked);
          tr.querySelector('[data-ck]').checked = e.target.checked;
        });
        syncChecks();
      });
      q('#pager').addEventListener('click', e => { const b = e.target.closest('[data-pg]'); if (b && !b.disabled) { page = +b.dataset.pg; render(); } });
      let qt; q('#q').addEventListener('input', e => { clearTimeout(qt); qt = setTimeout(() => { f.q = e.target.value.trim(); page = 1; render(); }, 250); });
      q('#fch').addEventListener('change', e => { f.ch = e.target.value; page = 1; render(); });
      q('#fst').addEventListener('change', e => { f.st = e.target.value; page = 1; render(); });
      $$('.sev-card', root).forEach(c => c.addEventListener('click', () => { f.sev = f.sev === c.dataset.sev ? 'all' : c.dataset.sev; page = 1; render(); }));
      q('#reset').addEventListener('click', () => {
        Object.assign(f, { q: '', sev: 'all', ch: 'all', st: 'all' });
        q('#q').value = ''; q('#fch').value = 'all'; q('#fst').value = 'all'; page = 1; render();
      });
      batchBtn.addEventListener('click', async () => {
        const n = sel.size;
        const ok = await confirmDialog({ title: `批量处置 ${n} 个事件`, text: '选中的事件将被标记为「已处置」并归档，同时记录到审计日志中。', okText: '确认处置' });
        if (!ok) return;
        const ids = [...sel];
        act(batchBtn, () => API.post('/incidents/batch-resolve', { ids }), r => {
          D.incidents.forEach(i => { if (sel.has(i.id) && (i.status === 'pending' || i.status === 'processing')) i.status = 'resolved'; });
          sel.clear(); render(); UI.updateNav();
          toast(`已批量处置 ${r.resolved} 个事件${r.resolved < n ? `（${n - r.resolved} 个已关闭的事件被跳过）` : ''}`, { type: 'success', title: '处置完成' });
        });
      });
      q('[data-act="export"]').addEventListener('click', () => UI.task(() => API.post('/exports', { kind: 'incidents', filter: { q: f.q, sev: f.sev, ch: f.ch, st: f.st } })));
      // 其他管理员处置事件或有新事件时刷新当前页
      let rt; const soon = () => { clearTimeout(rt); rt = setTimeout(render, 600); };
      UI.listen('incidents.changed', soon);
      UI.listen('incident', () => { if (page === 1) soon(); });
      UI.onCleanup(() => clearTimeout(rt));
      render();
    }
  };
})();
