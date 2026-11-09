/* 审计日志 */
(function () {
  'use strict';
  const { D, ic, esc, fmt, fmtTime, avatar, toast, seg, initSeg, card, pagerHtml, act } = UI;
  const TYPE_CLS = { '策略变更': 'b-info', '事件处置': 'b-success', '登录': 'b-primary', '终端操作': 'b-purple', '数据导出': 'b-warning', '配置变更': 'b-info', '白名单': '', '外发审批': 'b-success', '规则变更': 'b-info', '权限变更': 'b-purple', '越权访问': 'b-danger' };

  UI.pages.audit = {
    title: '审计日志', icon: 'list',
    html() {
      return `
      <div class="page-head">
        <div><h1>审计日志</h1><p>记录所有管理员操作，满足等保 2.0 与 ISO 27001 审计留痕要求，日志防篡改存储</p></div>
        <div class="head-actions"><button class="btn" data-act="verify">${ic('shield-check')}完整性校验</button><button class="btn btn-primary" data-act="export" data-perm="audit:exp">${ic('download')}导出日志</button></div>
      </div>
      ${card('操作记录', `
        <div class="toolbar">
          <div class="search-box">${ic('search')}<input class="input" id="aq" placeholder="搜索操作人、操作内容、IP…"></div>
          <select class="input" id="aty" aria-label="操作类型"><option value="all">全部类型</option>${D.auditTypes.map(t => `<option>${t}</option>`).join('')}</select>
          ${seg('ar', [['all', '全部结果'], ['ok', '成功'], ['fail', '失败']], 'all')}
        </div>
        <div class="table-wrap"><table class="table"><thead><tr><th>时间</th><th>操作人</th><th>角色</th><th>操作类型</th><th>操作内容</th><th>来源 IP</th><th>结果</th></tr></thead><tbody id="arows"></tbody></table></div>
        <div class="pager" id="apager"></div>`, { sub: '每条日志以 SHA-256 哈希链接入前一条，任何篡改都会被校验发现', extra: '<span class="tag" id="vTag">' + ic('lock') + '未校验</span><span class="muted small" id="aCnt"></span>' })}`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      const f = { q: '', type: 'all', r: 'all' }, per = 12; let page = 1;
      let seq = 0;
      async function render() {
        const my = ++seq;
        let r;
        try { r = await API.get('/audit' + API.qs({ q: f.q, type: f.type, result: f.r, page, per })); } catch (e) { UI.apiError(e); return; }
        if (my !== seq || !root.isConnected) return;
        const pages = Math.max(1, Math.ceil(r.total / per));
        if (page > pages) { page = pages; return render(); }
        q('#arows').innerHTML = r.items.map((a, i) => `<tr style="--i:${i}">
          <td class="mono muted">${fmtTime(a.ts)}</td>
          <td><div class="u-cell">${avatar(a.op, 'sm')}<b>${esc(a.op)}</b></div></td>
          <td class="muted">${esc(a.role)}</td>
          <td><span class="tag ${TYPE_CLS[a.type] || ''}">${esc(a.type)}</span></td>
          <td style="white-space:normal;min-width:260px">${esc(a.detail)}<small class="muted mono hash" title="${a.hash}">#${a.hash.slice(0, 12)}</small></td>
          <td class="mono">${esc(a.ip)}</td>
          <td>${a.ok ? '<span class="status st-resolved">成功</span>' : `<span class="status st-pending">失败 · ${esc(a.reason)}</span>`}</td></tr>`).join('')
          || `<tr><td colspan="7"><div class="empty-st">${ic('list')}<p>没有符合条件的日志</p></div></td></tr>`;
        q('#apager').innerHTML = pagerHtml(page, pages, r.total, per);
        q('#aCnt').textContent = `共 ${fmt(r.total)} 条`;
      }
      let t; q('#aq').addEventListener('input', e => { clearTimeout(t); t = setTimeout(() => { f.q = e.target.value.trim(); page = 1; render(); }, 160); });
      q('#aty').addEventListener('change', e => { f.type = e.target.value; page = 1; render(); });
      initSeg(root, 'ar', v => { f.r = v; page = 1; render(); });
      q('#apager').addEventListener('click', e => { const b = e.target.closest('[data-pg]'); if (b && !b.disabled) { page = +b.dataset.pg; render(); } });
      q('[data-act="export"]').addEventListener('click', () => UI.task(() => API.post('/exports', { kind: 'audit', filter: { q: f.q, type: f.type, result: f.r } })));
      q('[data-act="verify"]').addEventListener('click', e => act(e.currentTarget, () => API.get('/audit/verify'), r => {
        const tag = q('#vTag');
        tag.className = 'tag ' + (r.ok ? 'b-success' : 'b-danger');
        tag.innerHTML = ic(r.ok ? 'shield-check' : 'alert') + (r.ok ? '完整性校验通过' : '哈希链断裂');
        toast(r.ok ? `已校验 ${fmt(r.count)} 条日志的哈希链，未发现篡改` : `哈希链在 ${esc(r.broken)} 处断裂，日志可能被篡改`, { type: r.ok ? 'success' : 'error', title: r.ok ? '完整性校验通过' : '发现异常' });
        render();
      }));
      render();
    }
  };
})();
