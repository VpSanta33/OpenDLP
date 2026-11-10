/* 敏感数据发现 */
(function () {
  'use strict';
  const { D, C, ic, fmt, esc, relTime, countUp, toast, card } = UI;

  const LV = [['绝密', 'critical', '核心源代码、未公开财报'], ['机密', 'high', '客户数据、合同与报价'], ['内部', 'medium', '内部制度、会议纪要'], ['公开', 'low', '官网资料、宣传册']];
  const TYPES = ['文件服务器', '数据库', '对象存储', '协作平台', '邮件系统', '终端'];
  const riskCls = r => r >= 80 ? 'b-danger' : r >= 60 ? 'b-warning' : 'b-success';

  function repoRows() {
    if (!D.repos.length) return `<tr><td colspan="6"><div class="empty-st">${ic('database')}<p>尚未登记数据源。本项目不包含存量数据扫描器；登记后由外部扫描工具调用 /api/v1/ingest/discovery 回传结果</p></div></td></tr>`;
    return D.repos.map((r, i) => {
      const ratio = r.total ? r.sens / r.total * 100 : 0;
      return `<tr style="--i:${i}"><td><div class="repo"><span class="repo-ic">${ic(r.icon)}</span><div><b>${esc(r.name)}</b><small>${esc(r.type)}</small></div></div></td>
        <td>${r.last ? fmt(r.total) : '-'}</td><td><b>${r.last ? fmt(r.sens) : '-'}</b></td>
        <td>${r.last ? `<div class="ratio"><div class="meter"><i class="${ratio > 10 ? 'hot' : ratio > 2 ? 'warm' : ''}" style="--w:${Math.min(100, ratio * 3.2).toFixed(1)}%;--d:${0.2 + i * 0.07}s"></i></div><span>${ratio.toFixed(2)}%</span></div>` : '<span class="muted">待扫描</span>'}</td>
        <td>${r.last ? `<span class="risk-n tag ${riskCls(r.risk)}">${r.risk}</span>` : '-'}</td>
        <td class="muted">${r.last ? relTime(r.last) : '尚无回传结果'}</td></tr>`;
    }).join('');
  }

  UI.pages.discovery = {
    title: '敏感数据发现', icon: 'file-search',
    html() {
      const sum = k => D.repos.reduce((s, r) => s + ((r.levels || {})[k] || 0), 0);
      const scanned = D.repos.filter(r => r.last), total = scanned.reduce((s, r) => s + r.total, 0), sens = scanned.reduce((s, r) => s + r.sens, 0);
      const last = Math.max(0, ...D.repos.map(r => r.last || 0));
      return `
      <div class="page-head">
        <div><h1>敏感数据发现</h1><p>登记数据资产，汇总外部扫描工具回传的对象数、敏感对象与分级分布</p></div>
        <div class="head-actions"><button class="btn" data-act="add" data-perm="discovery:op">${ic('plus')}添加数据源</button></div>
      </div>
      <div class="mini-stats">
        <div class="mini"><span class="mini-ic mi-primary">${ic('database')}</span><div><span>数据源</span><b>${D.repos.length}</b></div></div>
        <div class="mini"><span class="mini-ic mi-muted">${ic('file')}</span><div><span>已扫描对象</span><b>${fmt(total)}</b></div></div>
        <div class="mini"><span class="mini-ic mi-danger">${ic('lock')}</span><div><span>敏感对象</span><b>${fmt(sens)}</b></div></div>
        <div class="mini"><span class="mini-ic mi-success">${ic('clock')}</span><div><span>最近扫描</span><b style="font-size:16px">${last ? relTime(last) : '暂无'}</b></div></div>
      </div>
      <div class="grid">
        ${card('数据源资产', `<div class="table-wrap"><table class="table"><thead><tr><th>数据源</th><th>对象总数</th><th>敏感对象</th><th>敏感占比</th><th>风险评分</th><th>上次回传</th></tr></thead><tbody id="repoRows">${repoRows()}</tbody></table></div>`, { cls: 'span-2', sub: '扫描结果由外部扫描工具通过接口回传' })}
        ${card('数据分级分布', sum('绝密') + sum('机密') + sum('内部') + sum('公开') ? '<div id="lvlDonut"></div>' : `<div class="empty-st">${ic('pie')}<p>暂无分级数据</p></div>`, { sub: '按密级统计已识别对象' })}
      </div>
      <div class="levels">${LV.map(l => `<div class="lvl" style="--c:var(--sev-${l[1]})"><div class="lvl-top"><span>${l[0]}级数据</span>${ic('lock')}</div><b data-count="${sum(l[0])}">0</b><p>${l[2]}</p></div>`).join('')}</div>`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      const sum = k => D.repos.reduce((s2, r) => s2 + ((r.levels || {})[k] || 0), 0);
      if (q('#lvlDonut')) C.donut(q('#lvlDonut'), { label: '分级对象', items: LV.map(l => ({ name: l[0], value: sum(l[0]), color: 'sev-' + l[1] })) });
      root.querySelectorAll('[data-count]').forEach(el => countUp(el, +el.dataset.count, { from: 0, dur: 1400 }));
      q('[data-act="add"]').addEventListener('click', () => {
        const { panel, close } = UI.openLayer('modal modal-sm', `<div class="md-head"><div><h2>添加数据源</h2><p>登记后由外部扫描工具按数据源名称回传结果</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
          <div class="md-body"><div class="field"><label class="lbl">数据源地址 <em>*</em></label><input class="input" id="rName" placeholder="例如 \\\\fs02.corp\\共享 或 mysql://crm-db/crm"></div>
          <div class="field"><label class="lbl">类型</label><select class="input" id="rType" style="width:100%">${TYPES.map(t => `<option>${t}</option>`).join('')}</select></div></div>
          <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('plus')}添加</button></div>`);
        panel.querySelector('[data-ok]').addEventListener('click', ev => {
          const name = panel.querySelector('#rName').value.trim();
          if (!name) { panel.querySelector('#rName').classList.add('err'); return; }
          UI.act(ev.currentTarget, () => API.post('/discovery/repos', { name, type: panel.querySelector('#rType').value }), rp => {
            D.repos.push(rp); close(); UI.rerender(); toast(`数据源「${esc(rp.name)}」已登记`, { type: 'success' });
          });
        });
      });
    }
  };
})();
