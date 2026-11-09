/* 报表中心：合规报告模板、在线预览、定时推送、历史归档 */
(function () {
  'use strict';
  const { D, C, ic, $$, fmt, esc, fmtTime, relTime, toast, card, openLayer, act, seg, initSeg } = UI;

  const TPL = [
    { key: 'monthly', name: '数据安全合规月报', icon: 'shield-check', color: 'c1', desc: '汇总月度事件、策略命中、终端覆盖率与合规项检查结果', tags: ['数据安全法', 'PIPL'], pages: 18 },
    { key: 'djbh', name: '等保 2.0 数据安全自查报告', icon: 'stamp', color: 'c4', desc: '对照 GB/T 22239-2019 第三级「数据完整性 / 保密性 / 备份恢复」逐项自查', tags: ['等保 2.0', '三级'], pages: 26 },
    { key: 'pipl', name: '个人信息保护合规审计报告', icon: 'user-check', color: 'c2', desc: '依据 PIPL 第 54 条，统计个人信息处理、跨境传输与去标识化情况', tags: ['PIPL', 'GB/T 35273'], pages: 21 },
    { key: 'weekly', name: '事件处置周报', icon: 'activity', color: 'c3', desc: '处置 SLA 达成率、平均响应时长、误报率与 TOP 风险事件', tags: ['运营'], pages: 8 },
    { key: 'dept', name: '部门风险排名', icon: 'chart-bar', color: 'c5', desc: '按部门统计风险评分、违规人次与环比趋势，支持下发部门负责人', tags: ['运营', '管理'], pages: 6 },
    { key: 'exec', name: '高管安全简报', icon: 'file-text', color: 'c6', desc: '一页纸呈现整体安全态势、关键风险与改进建议，适合董事会汇报', tags: ['管理层'], pages: 4 }
  ];
  const tplOf = k => TPL.find(t => t.key === k) || TPL[0];
  // 无运维查看权限的角色拿不到集成数据，此时返回 undefined（不确定）
  const smtpReady = () => D.integrations ? D.integrations.some(i => i.key === 'smtp' && i.st !== 'off') : undefined;
  const fmtAt = ms => new Date(ms).toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
  const lastMonth = () => { const d = new Date(); d.setMonth(d.getMonth() - 1); return `${d.getFullYear()} 年 ${d.getMonth() + 1} 月`; };

  async function preview(t) {
    let db;
    try { db = await API.get('/dashboard?range=30d'); } catch (e) { UI.apiError(e); return; }
    const inc = D.incidents, crit = inc.filter(i => i.severity === 'critical').length;
    const resolved = inc.filter(i => i.status === 'resolved' || i.status === 'fp').length;
    const checks = [['敏感数据识别与分类分级', 'ok'], ['数据外发渠道管控（邮件 / USB / 云盘 / IM / Web / 打印）', 'ok'], ['重要数据操作审计日志留存 ≥ 180 天', 'ok'], ['管理员三员分立与双因素认证', 'warn'], ['个人信息跨境传输评估', 'warn'], ['数据泄露应急预案与演练', 'ok']];
    const { panel, close } = openLayer('modal modal-lg', `
      <div class="md-head"><div><h2>${t.name} · 预览</h2><p>近 30 天实时数据 · 全集团 · 完整报告由服务端生成</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
      <div class="md-body rp-prev-wrap">
        <article class="paper">
          <div class="pp-cover"><span class="brand-logo">${ic('shield-check')}</span><div><small>OpenDLP · 数据安全报告</small><h1>${t.name}</h1><p>报告周期：${lastMonth()}　　密级：<b>内部</b>　　编制：安全运营中心</p></div></div>
          <h3>一、总体态势</h3>
          <div class="pp-kpi"><div><b>${fmt(db.kpi.events)}</b><span>外发检测</span></div><div><b>${fmt(db.kpi.blocked)}</b><span>阻断外发</span></div><div><b>${Math.round(resolved / Math.max(1, inc.length) * 100)}%</b><span>处置完成率</span></div><div><b>${(db.kpi.online / Math.max(1, db.kpi.deployed) * 100).toFixed(1)}%</b><span>终端在线率</span></div></div>
          <p class="pp-t">近 30 天共检测数据外发行为 ${fmt(db.kpi.events)} 次${db.kpi.delta.events != null ? `（环比 ${db.kpi.delta.events > 0 ? '+' : ''}${db.kpi.delta.events}%）` : ''}，阻断 ${fmt(db.kpi.blocked)} 次，产生 DLP 事件 ${fmt(inc.length)} 起，其中严重事件 ${crit} 起。综合风险评分 ${db.risk.score}（${db.risk.level}）。</p>
          <h3>二、外发渠道分布</h3>
          <div class="pp-bars" id="ppBars"></div>
        </article>
        <article class="paper">
          <h3>三、合规项检查</h3>
          <table class="pp-tbl"><thead><tr><th>检查项</th><th>依据</th><th>结果</th></tr></thead><tbody>
            ${checks.map(([c, s], i) => `<tr><td>${c}</td><td class="muted">${['数据安全法 第 21 条', 'GB/T 22239 8.1.4', '网络安全法 第 21 条', 'GB/T 22239 8.1.4.2', 'PIPL 第 38 条', '数据安全法 第 29 条'][i]}</td><td>${s === 'ok' ? `<span class="ok-t">${ic('check')}符合</span>` : `<span class="warn-c">${ic('alert')}部分符合</span>`}</td></tr>`).join('')}
          </tbody></table>
          <h3>四、改进建议</h3>
          <ol class="pp-ol"><li>为 2 名未启用 MFA 的管理员账号强制开启双因素认证。</li><li>对新加坡子公司的设计图纸同步行为补充数据出境安全评估。</li><li>将「离职员工高风险行为监控」策略覆盖范围扩展至外包人员。</li></ol>
          <div class="pp-foot">OpenDLP 自动生成 · ${fmtTime(Date.now())} · 第 2 页 / 共 ${t.pages} 页</div>
        </article>
      </div>
      <div class="md-foot"><span class="muted small">${ic('lock', 'ic-in')}生成与下载行为将记录到审计日志</span><span class="sp"></span><button class="btn" data-close>关闭</button><button class="btn btn-primary" data-gen data-perm="reports:exp">${ic('download')}生成完整报告</button></div>`);
    C.bars(panel.querySelector('#ppBars'), db.channels.map((c, i) => ({ name: D.chMap[c.key].name, value: c.value, color: 'c' + (i + 1) })));
    UI.applyPerms(panel);
    panel.querySelector('[data-gen]').addEventListener('click', () => { close(); generate(t); });
  }

  function generate(t, quick) {
    const run = body => UI.task(() => API.post('/reports', Object.assign({ tpl: t.key }, body)));
    if (quick) { run({ range: 'lm', fmt: 'HTML' }); return; }
    const { panel, close } = openLayer('modal', `
      <div class="md-head"><div><h2>生成报告</h2><p>${t.name} · 预计 ${t.pages} 页</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
      <div class="md-body">
        <div class="field"><label class="lbl">统计周期</label>${seg('rg', [['lm', '上月'], ['q', '本季度'], ['y', '本年度'], ['c', '自定义']], 'lm')}
          <div class="date-r" id="dr"><input type="date" class="input" id="dFrom" value="2026-10-01"><span class="muted">至</span><input type="date" class="input" id="dTo" value="2026-10-31"></div></div>
        <div class="field"><label class="lbl">数据范围</label><select class="input" id="scope"><option>全集团</option>${D.depts.map(d => `<option>${d}</option>`).join('')}</select></div>
        <div class="field"><label class="lbl">输出格式</label><div class="opt-grid" id="fmt">${[['HTML', 'file-text', 'HTML（可打印为 PDF）'], ['CSV', 'grid', 'CSV 数据明细']].map(([f, i, l], k) => `<button class="opt ${k ? '' : 'on'}" data-f="${f}">${ic(i)}${l}</button>`).join('')}</div></div>
        <div class="field"><label class="lbl">包含章节</label><div class="chips" id="secs">${['总体态势', '渠道分析', '高风险用户', '策略有效性', '合规项检查', '改进建议', '附录：事件明细'].map((s, i) => `<span class="chip ${i < 6 ? 'on' : ''}">${ic('check')}${s}</span>`).join('')}</div></div>
        
      </div>
      <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('play')}开始生成</button></div>`);
    let rg = 'lm';
    initSeg(panel, 'rg', v => { rg = v; panel.querySelector('#dr').classList.toggle('show', v === 'c'); });
    panel.querySelector('#fmt').addEventListener('click', e => { const b = e.target.closest('.opt'); if (!b) return; $$('.opt', panel).forEach(x => x.classList.toggle('on', x === b)); });
    panel.querySelector('#secs').addEventListener('click', e => { const c = e.target.closest('.chip'); c && c.classList.toggle('on'); });
    panel.querySelector('[data-ok]').addEventListener('click', () => {
      close();
      run({ range: rg, from: panel.querySelector('#dFrom').value, to: panel.querySelector('#dTo').value, fmt: panel.querySelector('#fmt .opt.on').dataset.f, scope: panel.querySelector('#scope').value });
    });
  }

  UI.pages.reports = {
    title: '报表中心', icon: 'pie',
    html() {
      return `
      <div class="page-head">
        <div><h1>报表中心</h1><p>一键生成合规报告与运营报表，支持在线预览、定时推送与加密归档</p></div>
        <div class="head-actions"><button class="btn btn-primary" id="newSch" data-perm="reports:op">${ic('calendar')}新建定时报表</button></div>
      </div>
      <div class="rp-grid">${TPL.map((t, i) => `
        <article class="rp-tpl" style="--c:var(--${t.color});--i:${i}" data-k="${t.key}">
          <div class="rp-top"><span class="rp-ic">${ic(t.icon)}</span><div class="rp-tags">${t.tags.map(x => `<span class="tag">${x}</span>`).join('')}</div></div>
          <h3>${t.name}</h3><p>${t.desc}</p>
          <div class="rp-foot"><span class="muted small">${ic('file-text')}约 ${t.pages} 页</span><span class="sp"></span><button class="btn btn-sm btn-ghost" data-pv>${ic('eye')}预览</button><button class="btn btn-sm" data-gen data-perm="reports:exp">${ic('download')}生成</button></div>
        </article>`).join('')}</div>
      <div class="grid g2">
        ${card('定时报表', '<div class="table-wrap"><table class="table compact-t"><thead><tr><th>报表</th><th>执行周期</th><th>接收人</th><th>下次执行 / 最近结果</th><th>启用</th><th></th></tr></thead><tbody id="sch"></tbody></table></div>', { sub: '到期自动生成并以邮件附件发送' })}
        ${card('历史报告', '<div class="table-wrap"><table class="table compact-t"><thead><tr><th>报告名称</th><th>格式</th><th>生成时间</th><th>生成人</th><th></th></tr></thead><tbody id="his"></tbody></table></div>', { sub: '加密归档，保留 3 年', extra: '<span class="muted small" id="hisCnt"></span>' })}
      </div>`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      const FC = { HTML: 'b-primary', CSV: 'b-success' };
      function renderSch() {
        q('#sch').innerHTML = D.reportSchedules.map((s, i) => `<tr style="--i:${i}" data-id="${s.id}"><td><b class="rn">${esc(s.name)}</b><small class="muted to">${s.fmt}</small></td><td>${ic('clock', 'ic-in')}${esc(s.cron)}</td><td>${s.to.slice(0, 2).map(x => `<span class="tag mono" title="${esc(x)}">${esc(x)}</span>`).join(' ')}${s.to.length > 2 ? ` <span class="muted small">等 ${s.to.length} 人</span>` : ''}</td>
          <td class="muted">${s.on ? fmtAt(s.next) : '已暂停'}${s.lastAt ? `<small style="display:block" class="${s.lastErr ? 'warn-c' : 'ok-t'}" title="${esc(s.lastErr || '')}">${fmtAt(s.lastAt)} ${s.lastErr ? '发送失败：' + esc(s.lastErr.slice(0, 24)) : '已发送'}</small>` : ''}</td>
          <td><label class="switch sm"><input type="checkbox" data-sw ${s.on ? 'checked' : ''} ${UI.canDo('reports', 'op') ? '' : 'disabled'} aria-label="启用"><span></span></label></td>
          <td class="acts"><button class="btn btn-sm btn-ghost" data-run ${UI.canDo('reports', 'exp') ? '' : 'disabled'}>${ic('play')}立即执行</button>${UI.canDo('reports', 'op') ? `<button class="icon-btn sm" data-del title="删除">${ic('trash')}</button>` : ''}</td></tr>`).join('') || '<tr><td colspan="6" class="muted" style="text-align:center;padding:24px">暂无定时报表</td></tr>';
      }
      function renderHis() {
        q('#his').innerHTML = D.reportHistory.slice(0, 8).map((h, i) => `<tr style="--i:${i}" class="${h.fresh ? 'fresh-row' : ''}"><td><div class="file-cell" title="${esc(h.name)}">${ic('file-text')}<span>${esc(h.name)}</span></div></td><td><span class="tag ${FC[h.fmt]}">${h.fmt}</span> <span class="muted small">${h.size}</span></td><td class="muted">${fmtTime(h.ts)}</td><td>${esc(h.by)}</td><td><button class="icon-btn sm" data-dl="${h.id}" aria-label="下载">${ic('download')}</button></td></tr>`).join('');
        q('#hisCnt').textContent = `共 ${D.reportHistory.length} 份`;
        D.reportHistory.forEach(h => { h.fresh = false; });
      }
      UI.listen('reports.changed', async () => {
        try { const r = await API.get('/reports'); const n = D.reportHistory.length; D.reportHistory = r.history; D.reportSchedules = r.schedules; if (D.reportHistory[0] && r.history.length > n) D.reportHistory[0].fresh = true; renderHis(); renderSch(); } catch (e) { /* 忽略 */ }
      });
      q('.rp-grid').addEventListener('click', e => {
        const c = e.target.closest('.rp-tpl'); if (!c) return;
        const t = tplOf(c.dataset.k);
        if (e.target.closest('[data-gen]')) { if (!e.target.closest('[data-gen]').disabled) generate(t); }
        else preview(t);
      });
      q('#sch').addEventListener('click', e => {
        const tr = e.target.closest('tr[data-id]'); if (!tr) return;
        const s = D.reportSchedules.find(x => x.id === tr.dataset.id);
        if (e.target.matches('[data-sw]')) {
          const want = e.target.checked;
          API.patch('/report-schedules/' + encodeURIComponent(s.id), { on: want }).then(upd => { Object.assign(s, upd); renderSch(); toast(`定时报表「${esc(s.name)}」已${s.on ? '启用' : '暂停'}`, { type: s.on ? 'success' : 'warning' }); })
            .catch(err => { e.target.checked = !want; UI.apiError(err); });
        } else if (e.target.closest('[data-run]')) UI.task(() => API.post(`/report-schedules/${encodeURIComponent(s.id)}/run`));
        else if (e.target.closest('[data-del]')) {
          UI.confirmDialog({ title: `删除定时报表「${esc(s.name)}」`, text: '删除后不再自动生成与发送，已归档的历史报告不受影响。', okText: '删除', danger: true }).then(ok => ok &&
            act(e.target.closest('[data-del]'), () => API.del('/report-schedules/' + encodeURIComponent(s.id)), () => {
              D.reportSchedules = D.reportSchedules.filter(x => x !== s); renderSch(); toast(`定时报表「${esc(s.name)}」已删除`, { type: 'success' });
            }));
        }
      });
      q('#his').addEventListener('click', e => { const b = e.target.closest('[data-dl]'); if (b) API.download(`/api/v1/reports/${encodeURIComponent(b.dataset.dl)}/download`); });
      q('#newSch').addEventListener('click', () => {
        const { panel, close } = openLayer('modal', `
          <div class="md-head"><div><h2>新建定时报表</h2><p>到期自动生成并推送给接收人</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
          <div class="md-body">
            <div class="field"><label class="lbl">报表模板</label><select class="input" id="sT">${TPL.map(t => `<option value="${t.key}">${t.name}</option>`).join('')}</select></div>
            <div class="grid g2" style="margin-bottom:0"><div class="field"><label class="lbl">执行周期</label><select class="input" id="sC"><option>每日 08:00</option><option selected>每周一 09:00</option><option>每月 1 日 08:00</option><option>每季度首日 09:00</option></select></div>
            <div class="field"><label class="lbl">输出格式</label><select class="input" id="sF"><option>HTML</option><option>CSV</option></select></div></div>
            <div class="field"><label class="lbl">接收人邮箱 <em>*</em> <span class="hint">多个用逗号或换行分隔，最多 20 个</span></label><textarea class="input mono" id="sR" rows="3" placeholder="soc@corp.example, ciso@corp.example"></textarea></div>
            <p class="muted small">${smtpReady() === false ? `${ic('alert', 'ic-in')}尚未配置「告警邮件 (SMTP)」集成，报表会生成并归档，但无法发送邮件。` : '报表将以附件形式通过「运维中心 → 告警邮件 (SMTP)」集成发送。'}</p>
          </div>
          <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('save')}创建</button></div>`);
        panel.querySelector('[data-ok]').addEventListener('click', e => {
          const to = panel.querySelector('#sR').value.split(/[\s,，;；]+/).map(x => x.trim()).filter(Boolean);
          panel.querySelector('#sR').classList.toggle('err', !to.length);
          if (!to.length) { toast('请至少填写一个接收人邮箱', { type: 'warning' }); return; }
          act(e.currentTarget, () => API.post('/report-schedules', { tpl: panel.querySelector('#sT').value, cron: panel.querySelector('#sC').value, to, fmt: panel.querySelector('#sF').value }), sc => {
            D.reportSchedules.unshift(sc);
            close(); renderSch(); toast(`定时报表「${esc(sc.name)}」已创建`, { type: 'success', title: '创建成功' });
          });
        });
      });
      renderSch(); renderHis();
    }
  };
})();
