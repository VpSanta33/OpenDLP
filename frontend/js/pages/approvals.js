/* 外发审批：敏感文件外发前的多级在线审批 */
(function () {
  'use strict';
  const { D, ic, $$, esc, fmtTime, relTime, avatar, countUp, toast, card, chIcon, pagerHtml, openLayer, confirmDialog, act, seg, initSeg } = UI;

  const ST = { pending: ['审批中', 'b-warning'], approved: ['已通过', 'b-success'], rejected: ['已驳回', 'b-danger'], expired: ['已过期', ''] };
  const LV = { '机密': 'b-danger', '秘密': 'b-warning', '内部': 'b-info' };
  const stTag = a => `<span class="tag ${ST[a.status][1]}">${ST[a.status][0]}</span>`;
  const lvTag = l => `<span class="tag ${LV[l]}">${ic('lock')}${l}</span>`;
  const mine = a => a.status === 'pending' && a.stage === 2;

  function sla(a) {
    if (a.status !== 'pending') return `<span class="muted small">—</span>`;
    const left = a.deadline - Date.now(), total = a.deadline - a.ts;
    const pct = Math.max(0, Math.min(100, left / total * 100));
    const h = Math.floor(Math.max(0, left) / 3600e3), m = Math.floor((Math.max(0, left) % 3600e3) / 60e3);
    const cls = left <= 0 ? 'over' : left < 2 * 3600e3 ? 'warn' : '';
    return `<div class="sla ${cls}"><span>${left <= 0 ? '已超时' : `剩余 ${h ? h + ' 小时 ' : ''}${m} 分`}</span><i><b style="width:${pct}%"></b></i></div>`;
  }
  function flowHtml(a) {
    const nodes = [['提交申请', a.user], ['部门负责人', a.leader], ['数据安全官', a.approver && a.stage >= 2 ? a.approver : (UI.me ? UI.me.name : '安全管理员')], ['加密外发', '系统自动']];
    const state = i => {
      if (a.status === 'approved') return 'done';
      if (a.status === 'rejected') return i < a.stage ? 'done' : i === a.stage ? 'rej' : 'wait';
      if (a.status === 'expired') return i < a.stage ? 'done' : i === a.stage ? 'exp' : 'wait';
      return i < a.stage ? 'done' : i === a.stage ? 'cur' : 'wait';
    };
    return `<div class="aflow">${nodes.map(([r, n], i) => `${i ? `<span class="af-line ${state(i - 1) === 'done' && state(i) !== 'wait' ? 'done' : ''}" style="--d:${i * 0.18}s"><i></i></span>` : ''}
      <div class="af-node ${state(i)}" style="--d:${i * 0.18}s"><b>${ic(state(i) === 'rej' ? 'x' : state(i) === 'done' ? 'check' : i === 3 ? 'lock' : 'user')}</b><span>${r}</span><small>${esc(n)}</small></div>`).join('')}</div>`;
  }

  function openApproval(id, onChange) {
    const a = D.approvals.find(x => x.id === id); if (!a) return;
    const dt = D.dtMap[a.dataType], ch = D.chMap[a.channel];
    const actionable = mine(a), other = a.status === 'pending' && a.stage < 2;
    const kv = [['申请人', `${a.user} · ${a.dept}`], ['外发方式', ch.name], ['接收方', a.to], ['文件大小', a.size], ['申请时间', fmtTime(a.ts)], ['审批时限', a.urgent ? '4 小时（加急）' : '24 小时']];
    const html = `
      <div class="dr-head">
        <div class="dr-meta">${lvTag(a.level)}<span class="mono muted">${a.id}</span>${stTag(a)}${a.urgent ? '<span class="tag b-danger">加急</span>' : ''}</div>
        <h2>${esc(a.file)}</h2><p>${esc(a.user)} 申请外发至 ${esc(a.to)} · ${relTime(a.ts)}</p>
        <button class="icon-btn dr-close" data-close aria-label="关闭">${ic('x')}</button>
      </div>
      <div class="dr-body">
        <h4 class="sec-t" style="margin-top:0">审批流程</h4>
        ${flowHtml(a)}
        <div class="callout ${a.risk >= 75 ? 'c-critical' : 'c-high'}" style="margin-top:16px">${ic('file-search')}<div>内容预检：识别到 <b>${dt.name} ${a.matches} 处</b>，文件密级 <b>${a.level}</b>，综合风险评分 <b>${a.risk}</b>。${a.risk >= 75 ? '建议强制加密并限制有效期。' : ''}</div></div>
        <div class="kv">${kv.map(([k, v]) => `<div><span>${k}</span><b title="${esc(v)}">${esc(v)}</b></div>`).join('')}</div>
        <h4 class="sec-t">申请理由</h4>
        <div class="quote">${esc(a.reason)}</div>
        ${actionable ? `
        <h4 class="sec-t">放行条件</h4>
        <div class="cond">
          <label class="set-row compact"><div><b>强制透明加密</b><small>接收方需使用授权阅读器打开${a.level === '机密' ? '（机密文件不可关闭）' : ''}</small></div><span class="switch"><input type="checkbox" id="cEnc" checked ${a.level === '机密' ? 'disabled' : ''}><span></span></span></label>
          <label class="set-row compact"><div><b>叠加数字水印</b><small>嵌入申请人、接收方与时间的隐式水印，可溯源</small></div><span class="switch"><input type="checkbox" id="cWm" checked><span></span></span></label>
          <label class="set-row compact"><div><b>禁止打印与二次转发</b></div><span class="switch"><input type="checkbox" id="cNp" ${a.risk >= 75 ? 'checked' : ''}><span></span></span></label>
          <div class="set-row compact"><div><b>文件有效期</b></div><select class="input" id="exp"><option value="3">3 天</option><option value="7" selected>7 天</option><option value="30">30 天</option></select></div>
          <div class="set-row compact"><div><b>最大打开次数</b></div><select class="input" id="maxo"><option value="5">5 次</option><option value="10" selected>10 次</option><option value="0">不限</option></select></div>
        </div>
        <h4 class="sec-t">审批意见 <small>驳回时必填</small></h4>
        <textarea class="input" id="cmt" rows="3" style="width:100%" placeholder="填写审批意见，将同步通知申请人"></textarea>
        <div class="field-err" id="cmtErr">驳回申请时请填写审批意见</div>` : `
        <h4 class="sec-t">审批记录</h4>
        <ol class="timeline">
          <li class="done" style="--i:0"><i></i><div><b>${esc(a.user)} 提交外发申请</b><p>${esc(a.reason)}</p><time>${fmtTime(a.ts)}</time></div></li>
          ${a.stage >= 2 || a.status !== 'pending' ? `<li class="done" style="--i:1"><i></i><div><b>${esc(a.leader)}（部门负责人）同意</b><p>业务需要，同意外发</p><time>${fmtTime(a.ts + 26 * 60e3)}</time></div></li>` : `<li class="current" style="--i:1"><i></i><div><b>等待 ${esc(a.leader)}（部门负责人）审批</b><p>已通过企业微信推送待办提醒</p></div></li>`}
          ${a.status === 'approved' ? `<li class="done" style="--i:2"><i></i><div><b>${esc(a.approver || '数据安全官')} 同意 · 加密外发</b><p>${esc(a.comment || '')}${a.conditions ? `（${a.conditions.encrypt ? '强制加密' : '不加密'}${a.conditions.watermark ? ' · 数字水印' : ''}${a.conditions.noPrint ? ' · 禁止打印' : ''} · 有效期 ${a.conditions.expireDays} 天）` : ''}</p><time>${fmtTime(a.decidedAt || a.ts)}</time></div></li>` : ''}
          ${a.status === 'rejected' ? `<li class="done rej" style="--i:2"><i></i><div><b>审批被驳回</b><p>${esc(a.approver || '')}：${esc(a.comment || '')}</p><time>${fmtTime(a.decidedAt || a.ts)}</time></div></li>` : ''}
          ${a.status === 'expired' ? `<li class="done" style="--i:2"><i></i><div><b>申请已过期</b><p>超过审批时限未处理，系统自动关闭</p><time>${fmtTime(a.deadline)}</time></div></li>` : ''}
        </ol>`}
      </div>
      <div class="dr-foot">
        ${actionable ? `<button class="btn" data-a="fwd" data-perm="approvals:op">${ic('send')}转交</button><button class="btn btn-danger-o" data-a="rej" data-perm="approvals:op">${ic('x')}驳回</button><button class="btn btn-primary" data-a="ok" data-perm="approvals:op">${ic('check')}同意外发</button>`
        : other ? `<button class="btn" data-close>关闭</button><button class="btn btn-primary" data-a="urge" data-perm="approvals:op">${ic('bell')}催办 ${esc(a.leader)}</button>`
          : `<button class="btn" data-close>关闭</button>`}
      </div>`;
    const { panel, close } = openLayer('drawer', html);
    const g = sel => panel.querySelector(sel);
    const done = (upd, msg, type) => {
      Object.assign(a, upd);
      g('.aflow').outerHTML = flowHtml(a);
      UI.updateNav(); onChange && onChange();
      toast(msg, { type: type || 'success', title: type === 'warning' ? '已驳回' : '审批完成' });
      setTimeout(close, 900);
    };
    const decide = (btn, body, msg, type) => act(btn, () => API.post(`/approvals/${encodeURIComponent(a.id)}/decision`, body), upd => done(upd, msg, type));
    g('.dr-foot').addEventListener('click', async e => {
      const b = e.target.closest('[data-a]'); if (!b || b.disabled) return;
      const k = b.dataset.a;
      if (k === 'urge') return act(b, () => API.post(`/approvals/${encodeURIComponent(a.id)}/urge`), r => toast(`已通过企业微信向 ${esc(r.leader)} 发送催办提醒`, { type: 'success', title: '催办成功' }));
      if (k === 'fwd') return forward(b);
      const cmt = g('#cmt');
      if (k === 'rej') {
        if (!cmt.value.trim()) { cmt.classList.add('err', 'shake'); g('#cmtErr').classList.add('show'); setTimeout(() => cmt.classList.remove('shake'), 500); cmt.focus(); return; }
        const ok = await confirmDialog({ title: '驳回外发申请', text: `将驳回 ${esc(a.user)} 的外发申请，并通知申请人。`, okText: '确认驳回', danger: true });
        if (!ok) return;
        return decide(b, { decision: 'reject', comment: cmt.value.trim() }, `已驳回 ${esc(a.user)} 的外发申请`, 'warning');
      }
      const conditions = { encrypt: g('#cEnc').checked, watermark: g('#cWm').checked, noPrint: g('#cNp').checked, expireDays: +g('#exp').value, maxOpens: +g('#maxo').value };
      decide(b, { decision: 'approve', comment: cmt.value.trim(), conditions }, `${esc(a.file)} 已加密并外发至 ${esc(a.to)}，有效期 ${conditions.expireDays} 天`);
    });
    function forward(btn) {
      if (!D.approvers.length) { toast('没有其他可转交的审批人', { type: 'warning' }); return; }
      const m = openLayer('modal modal-sm', `<div class="md-head"><div><h2>转交审批</h2><p>选择具有审批权限的管理员</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
        <div class="md-body"><select class="input" id="fwdTo" style="width:100%">${D.approvers.map(x => `<option value="${esc(x.acc)}">${esc(x.name)}（${esc(x.acc)}）</option>`).join('')}</select></div>
        <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('send')}转交</button></div>`);
      m.panel.querySelector('[data-ok]').addEventListener('click', ev => {
        const to = m.panel.querySelector('#fwdTo');
        act(ev.currentTarget, () => API.post(`/approvals/${encodeURIComponent(a.id)}/decision`, { decision: 'forward', to: to.value }), () => {
          m.close(); toast(`已转交给 ${esc(to.selectedOptions[0].textContent)}，您将收到处理结果通知`, { type: 'info', title: '已转交' });
        });
      });
    }
    g('#cmt') && g('#cmt').addEventListener('input', e => { e.target.classList.remove('err'); g('#cmtErr').classList.remove('show'); });
    UI.applyPerms(panel);
  }

  UI.pages.approvals = {
    title: '外发审批', icon: 'stamp',
    html() {
      return `
      <div class="page-head">
        <div><h1>外发审批</h1><p>敏感文件外发前的多级在线审批，审批通过后自动加密、加水印并限制时效</p></div>
        <div class="head-actions">
          <button class="btn" id="flowCfg">${ic('sliders')}审批流程配置</button>
          <button class="btn btn-primary" id="batchOk" data-perm="approvals:op" disabled>${ic('check')}批量同意<span class="cnt"></span></button>
        </div>
      </div>
      <div class="mini-stats">
        <div class="mini"><span class="mini-ic mi-warning">${ic('stamp')}</span><div><span>待我审批</span><b data-n="mine">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-danger">${ic('clock')}</span><div><span>2 小时内超时</span><b data-n="soon">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-success">${ic('check')}</span><div><span>近 7 天通过率</span><b><em data-n="rate">0</em><small>%</small></b></div></div>
        <div class="mini"><span class="mini-ic mi-primary">${ic('activity')}</span><div><span>平均审批时长</span><b>${(() => { const d = D.approvals.filter(a => a.decidedAt && a.status !== "expired"); return d.length ? Math.round(d.reduce((t, a) => t + a.decidedAt - a.ts, 0) / d.length / 60e3) + "<small> 分钟</small>" : "-"; })()}</b></div></div>
      </div>
      ${card('审批单', `
        <div class="toolbar">
          ${seg('tab', [['mine', '待我审批'], ['other', '待他人审批'], ['done', '已处理'], ['all', '全部']], 'mine')}
          <div class="search-box">${ic('search')}<input class="input" id="q" placeholder="搜索申请人、文件、接收方…"></div>
          <span class="sp"></span><span class="muted small" id="cnt"></span>
        </div>
        <div class="table-wrap"><table class="table">
          <thead><tr><th class="ck"><input type="checkbox" id="ckAll" aria-label="全选"></th><th>申请单</th><th>申请人</th><th>外发文件</th><th>外发方式 / 接收方</th><th>申请理由</th><th>审批时效</th><th>状态</th><th></th></tr></thead>
          <tbody id="rows"></tbody></table></div>
        <div class="pager" id="pager"></div>`, { sub: '审批链：申请人 → 部门负责人 → 数据安全官 → 加密外发' })}`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      let tab = 'mine', kw = '', page = 1; const per = 8, sel = new Set();
      const list = () => D.approvals.filter(a =>
        (tab === 'all' || (tab === 'mine' && mine(a)) || (tab === 'other' && a.status === 'pending' && a.stage < 2) || (tab === 'done' && a.status !== 'pending')) &&
        (!kw || (a.user + a.file + a.to + a.id + a.dept).toLowerCase().includes(kw.toLowerCase())));
      function stats() {
        countUp(q('[data-n="mine"]'), D.approvals.filter(mine).length);
        countUp(q('[data-n="soon"]'), D.approvals.filter(a => a.status === 'pending' && a.deadline - Date.now() < 2 * 3600e3).length);
        const done = D.approvals.filter(a => a.status !== 'pending');
        countUp(q('[data-n="rate"]'), Math.round(done.filter(a => a.status === 'approved').length / Math.max(1, done.length) * 100));
      }
      function render() {
        const L = list(), pages = Math.max(1, Math.ceil(L.length / per));
        page = Math.min(page, pages);
        const rows = L.slice((page - 1) * per, page * per);
        q('#rows').innerHTML = rows.length ? rows.map((a, i) => `<tr class="clickable ${sel.has(a.id) ? 'selected' : ''}" data-id="${a.id}" style="--i:${i}">
          <td class="ck">${mine(a) ? `<input type="checkbox" data-ck ${sel.has(a.id) ? 'checked' : ''} aria-label="选择">` : ''}</td>
          <td><div class="dt-cell"><span class="mono">${a.id}</span><small>${relTime(a.ts)}${a.urgent ? ' · <em class="urg">加急</em>' : ''}</small></div></td>
          <td><div class="u-cell">${avatar(a.user, 'sm')}<div><b>${esc(a.user)}</b><small>${a.dept}</small></div></div></td>
          <td><div class="file-cell" title="${esc(a.file)}">${ic('file')}<span>${esc(a.file)}</span></div><div style="margin-top:3px">${lvTag(a.level)} <span class="muted small">${D.dtMap[a.dataType].name} · ${a.size}</span></div></td>
          <td>${chIcon(a.channel)}<small class="muted to">${esc(a.to)}</small></td>
          <td><span class="reason" title="${esc(a.reason)}">${esc(a.reason)}</span></td>
          <td>${sla(a)}</td><td>${stTag(a)}</td>
          <td>${mine(a) ? `<button class="btn btn-sm btn-primary" data-open>审批</button>` : `<span class="row-go">${ic('chevron-right')}</span>`}</td></tr>`).join('')
          : `<tr><td colspan="9"><div class="empty-st">${ic('inbox')}<p>${tab === 'mine' ? '太棒了，没有待您审批的申请' : '没有符合条件的审批单'}</p></div></td></tr>`;
        q('#pager').innerHTML = pagerHtml(page, pages, L.length, per);
        q('#cnt').textContent = `共 ${L.length} 条`;
        q('#ckAll').disabled = tab !== 'mine' && tab !== 'all';
        syncBatch();
      }
      function syncBatch() {
        [...sel].forEach(id => { const a = D.approvals.find(x => x.id === id); if (!mine(a)) sel.delete(id); });
        const b = q('#batchOk'); b.disabled = !sel.size || !UI.canDo('approvals', 'op'); b.querySelector('.cnt').textContent = sel.size || '';
        const ids = $$('[data-ck]', root).map(c => c.closest('tr').dataset.id), ck = q('#ckAll');
        ck.checked = ids.length > 0 && ids.every(id => sel.has(id));
        ck.indeterminate = !ck.checked && ids.some(id => sel.has(id));
      }
      const refresh = () => { stats(); render(); };
      initSeg(root, 'tab', v => { tab = v; page = 1; render(); });
      let t; q('#q').addEventListener('input', e => { clearTimeout(t); t = setTimeout(() => { kw = e.target.value.trim(); page = 1; render(); }, 180); });
      q('#rows').addEventListener('click', e => {
        const tr = e.target.closest('tr[data-id]'); if (!tr) return;
        if (e.target.closest('[data-ck]')) { const id = tr.dataset.id; sel.has(id) ? sel.delete(id) : sel.add(id); tr.classList.toggle('selected', sel.has(id)); syncBatch(); return; }
        openApproval(tr.dataset.id, refresh);
      });
      q('#ckAll').addEventListener('change', e => { $$('[data-ck]', root).forEach(c => { const id = c.closest('tr').dataset.id; e.target.checked ? sel.add(id) : sel.delete(id); c.checked = e.target.checked; c.closest('tr').classList.toggle('selected', e.target.checked); }); syncBatch(); });
      q('#pager').addEventListener('click', e => { const b = e.target.closest('[data-pg]'); if (b && !b.disabled) { page = +b.dataset.pg; render(); } });
      q('#batchOk').addEventListener('click', async () => {
        const n = sel.size;
        const hi = D.approvals.filter(a => sel.has(a.id) && a.level === '机密').length;
        const ok = await confirmDialog({ title: `批量同意 ${n} 个外发申请`, text: `选中的文件将统一按「强制加密 + 数字水印 + 7 天有效期」放行。${hi ? `其中 ${hi} 个为机密文件，请确认已逐一核实。` : ''}`, okText: '确认同意' });
        if (!ok) return;
        act(q('#batchOk'), () => API.post('/approvals/batch-approve', { ids: [...sel] }), async r => {
          sel.clear();
          try { D.approvals = await API.get('/approvals'); } catch (e) { /* 忽略 */ }
          refresh(); UI.updateNav();
          toast(`已批量同意 ${r.approved} 个外发申请${r.skipped ? `，${r.skipped} 个已超时或已处理被跳过` : ''}`, { type: 'success', title: '审批完成' });
        });
      });
      q('#flowCfg').addEventListener('click', () => {
        const { panel, close } = openLayer('modal', `
          <div class="md-head"><div><h2>审批流程配置</h2><p>根据文件密级自动匹配审批链</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
          <div class="md-body">
            ${[['机密', '部门负责人 → 数据安全官 → CISO（金额/条数超阈值时）', '4 小时 / 24 小时', 'b-danger'], ['秘密', '部门负责人 → 数据安全官', '24 小时', 'b-warning'], ['内部', '部门负责人（可设置自动通过白名单接收方）', '48 小时', 'b-info']].map(([l, f, s, c]) => `
              <div class="flow-row"><span class="tag ${c}">${ic('lock')}${l}</span><div><b>${f}</b><small>审批时限：${s} · 超时自动驳回并通知申请人</small></div><button class="btn btn-sm btn-ghost">${ic('edit')}编辑</button></div>`).join('')}
            <label class="set-row"><div><b>白名单接收方自动通过</b><small>已签署 NDA 的合作伙伴域名（12 个）可跳过部门负责人审批</small></div><span class="switch"><input type="checkbox" checked><span></span></span></label>
            <label class="set-row"><div><b>审批人离线时自动转交代理人</b><small>根据 AD 中配置的直属上级 / 代理人关系</small></div><span class="switch"><input type="checkbox" checked><span></span></span></label>
          </div>
          <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok data-perm="approvals:cfg">${ic('save')}保存配置</button></div>`);
        const sw = panel.querySelectorAll('.set-row input');
        sw[0].checked = D.settings.apvAutoWhitelist !== false; sw[1].checked = D.settings.apvDelegate !== false;
        panel.querySelector('[data-ok]').addEventListener('click', e => act(e.currentTarget, () => API.put('/approvals/flow', { autoWhitelist: sw[0].checked, delegate: sw[1].checked }), () => {
          D.settings.apvAutoWhitelist = sw[0].checked; D.settings.apvDelegate = sw[1].checked;
          close(); toast('审批流程配置已保存，新提交的申请将按新流程执行', { type: 'success', title: '保存成功' });
        }));
        UI.applyPerms(panel);
      });
      const iv = setInterval(() => $$('tr[data-id]', root).forEach(tr => { const a = D.approvals.find(x => x.id === tr.dataset.id); const c = tr.children[6]; if (a && c) c.innerHTML = sla(a); }), 30000);
      UI.onCleanup(() => clearInterval(iv));
      UI.listen('approvals.refreshed', refresh);
      refresh();
    }
  };
})();
