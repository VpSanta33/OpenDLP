/* 用户风险画像（UEBA）：用户行为基线、风险评分、异常行为时间线 */
(function () {
  'use strict';
  const { D, C, ic, $$, esc, fmtTime, relTime, avatar, countUp, toast, card, sevBadge, actBadge, chIcon, act, confirmDialog, hue, seg, initSeg } = UI;

  const DIMS = ['外发频次', '数据敏感度', '非工作时间', '渠道多样性', '批量外发', '被阻断次数'];
  const emp = name => D.employees.find(e => e.name === name) || {};
  const watch = new Set();
  const DAY = 864e5;
  const isNight = ts => { const h = new Date(ts).getHours(); return h < 7 || h >= 22; };

  // 基于近 30 天 DLP 事件计算画像（评分规则见 scoreOf，部门基线为同部门用户各维度均值）
  function scoreOf(list, leaving) {
    const sev = list.reduce((s, i) => s + UI.SEV[i.severity].w, 0);
    return Math.min(99, Math.round(sev * 2.2 + list.filter(i => isNight(i.ts)).length * 3 + (leaving ? 20 : 0)));
  }
  function dimsOf(list) {
    const n = list.length || 1;
    return [
      Math.min(98, list.length * 8),
      Math.round(list.filter(i => i.severity === 'critical' || i.severity === 'high').length / n * 100),
      Math.min(98, list.filter(i => isNight(i.ts)).length * 15),
      Math.min(98, new Set(list.map(i => i.channel)).size * 16),
      Math.min(98, list.filter(i => i.matches >= 200).length * 20),
      Math.min(98, list.filter(i => i.action === 'block').length * 12)
    ];
  }
  let profiles = [];
  const build = () => {
    const by = {};
    D.incidents.forEach(i => { if (i.user) (by[i.user] = by[i.user] || []).push(i); });
    const now = Date.now();
    const list = Object.entries(by).map(([name, inc]) => {
      const e = emp(name), leaving = e.status === 'leaving', last = inc[0];
      const trend = [];
      for (let d = 29; d >= 0; d--) { const end = now - d * DAY; trend.push(scoreOf(inc.filter(i => i.ts <= end && i.ts > end - 7 * DAY), leaving)); }
      return { id: e.id || name, name, dept: e.dept || last.dept || '-', title: e.title || '—', host: last.host || '-', ip: last.ip || '-', fromDir: !!e.id,
        leaving, score: scoreOf(inc, leaving), dims: dimsOf(inc), trend, delta: trend[29] - trend[22], inc };
    });
    const depts = {};
    list.forEach(p => { (depts[p.dept] = depts[p.dept] || []).push(p.dims); });
    list.forEach(p => { const ds = depts[p.dept]; p.base = DIMS.map((_, k) => Math.round(ds.reduce((s, x) => s + x[k], 0) / ds.length)); });
    return list.sort((a, b) => b.score - a.score);
  };
  const level = s => s >= 80 ? ['高风险', 'danger'] : s >= 60 ? ['中风险', 'warning'] : s >= 40 ? ['低风险', 'primary'] : ['正常', 'success'];

  // 异常行为：由事件归纳（每项给出对评分的贡献）
  function anomalies(p) {
    const out = [], inc = p.inc, latest = l => l.reduce((a, b) => (a.ts > b.ts ? a : b));
    const add = (cond, sev, icon, title, text, pts, ts) => { if (cond) out.push({ sev, icon, title, text, add: pts, ts }); };
    const night = inc.filter(i => isNight(i.ts)), crit = inc.filter(i => i.severity === 'critical'), bulk = inc.filter(i => i.matches >= 200), blocked = inc.filter(i => i.action === 'block');
    add(p.leaving, 'critical', 'logout', '离职流程中仍有外发行为', `离职流程期间发生 ${inc.length} 起 DLP 事件`, 20, latest(inc).ts);
    add(crit.length, 'critical', 'zap', '严重级别外发', `${crit.length} 起严重事件，最近一次：${latest(crit.length ? crit : inc).file}`, crit.length * 8, latest(crit.length ? crit : inc).ts);
    add(night.length, 'high', 'clock', '非工作时间外发', `22:00 - 07:00 外发 ${night.length} 次，最近一次通过${(D.chMap[latest(night.length ? night : inc).channel] || {}).name || ''}`, night.length * 3, latest(night.length ? night : inc).ts);
    add(bulk.length, 'high', 'database', '批量敏感数据外发', `${bulk.length} 次单次命中 ≥ 200 处，最大 ${Math.max(0, ...bulk.map(i => i.matches))} 处`, bulk.length * 4, latest(bulk.length ? bulk : inc).ts);
    add(new Set(inc.map(i => i.channel)).size >= 3, 'medium', 'globe', '使用多种外发渠道', `近 30 天使用 ${new Set(inc.map(i => i.channel)).size} 种外发渠道`, 0, latest(inc).ts);
    add(blocked.length, 'medium', 'ban', '多次被策略阻断', `${blocked.length} 次外发被阻断`, 0, latest(blocked.length ? blocked : inc).ts);
    return out.sort((a, b) => b.ts - a.ts);
  }

  function radar(el, p) {
    const cx = 150, cy = 128, R = 92, n = DIMS.length;
    const pt = (k, v) => { const a = -Math.PI / 2 + k * 2 * Math.PI / n; return [cx + Math.cos(a) * R * v / 100, cy + Math.sin(a) * R * v / 100]; };
    const poly = vals => vals.map((v, k) => pt(k, v).map(x => x.toFixed(1)).join(',')).join(' ');
    let g = '';
    [25, 50, 75, 100].forEach(l => { g += `<polygon class="rd-ring" points="${poly(DIMS.map(() => l))}"/>`; });
    DIMS.forEach((d, k) => {
      const [x, y] = pt(k, 100), [lx, ly] = pt(k, 122);
      g += `<line class="rd-axis" x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/><text class="rd-lbl" x="${lx.toFixed(1)}" y="${(ly + 4).toFixed(1)}" text-anchor="${Math.abs(lx - cx) < 8 ? 'middle' : lx > cx ? 'start' : 'end'}">${d}</text>`;
    });
    el.innerHTML = `<svg viewBox="0 0 300 262" class="radar-c">${g}
      <polygon class="rd-base" points="${poly(p.base)}"/>
      <g class="rd-user"><polygon points="${poly(p.dims)}"/>${p.dims.map((v, k) => { const [x, y] = pt(k, v); return `<circle cx="${x.toFixed(1)}" cy="${y.toFixed(1)}" r="3.5"><title>${DIMS[k]}：${v}（部门基线 ${p.base[k]}）</title></circle>`; }).join('')}</g></svg>
      <div class="lg rd-lg"><span><i style="background:var(--danger)"></i>${esc(p.name)}</span><span><i class="dash"></i>部门基线</span></div>`;
  }

  UI.pages.ueba = {
    title: '用户风险画像', icon: 'radar',
    html() {
      watch.clear(); (D.watchlist || []).forEach(n => watch.add(n));
      profiles = build();
      const hi = profiles.filter(p => p.score >= 80).length, mid = profiles.filter(p => p.score >= 60 && p.score < 80).length;
      return `
      <div class="page-head">
        <div><h1>用户风险画像</h1><p>根据近 30 天 DLP 事件按规则计算每个用户的风险评分，并与所在部门平均水平对比</p></div>
        <div class="head-actions"><span class="pill">${ic('clock')}基于近 30 天 ${D.incidents.length} 起事件实时计算</span><button class="btn" id="exp" data-perm="incidents:exp">${ic('download')}导出严重事件</button></div>
      </div>
      <div class="mini-stats">
        <div class="mini"><span class="mini-ic mi-danger">${ic('zap')}</span><div><span>高风险用户</span><b data-n="${hi}">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-warning">${ic('alert')}</span><div><span>中风险用户</span><b data-n="${mid}">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-primary">${ic('eye')}</span><div><span>观察名单</span><b id="wCnt">${watch.size}</b></div></div>
        <div class="mini"><span class="mini-ic mi-muted">${ic('logout')}</span><div><span>离职流程中</span><b data-n="${profiles.filter(p => p.leaving).length}">0</b></div></div>
      </div>
      <div class="ub-wrap">
        <section class="card ub-list">
          <header class="card-h"><div><h3>风险排行</h3><p>按综合风险评分排序</p></div></header>
          <div class="ub-f">${seg('uf', [['all', '全部'], ['hi', '高风险'], ['watch', '观察名单'], ['leave', '离职中']], 'all')}</div>
          <ul id="ulist"></ul>
        </section>
        <div class="ub-main" id="prof"></div>
      </div>`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      let f = 'all', charts = [];
      const want = UI.params.get('u');
      if (!profiles.length) {
        root.querySelector('.ub-wrap').innerHTML = `<section class="card" style="grid-column:1/-1"><div class="empty-st">${ic('radar')}<p>近 30 天没有 DLP 事件，暂无可分析的用户行为</p></div></section>`;
        return;
      }
      let cur = (profiles.find(p => p.id === want || p.name === want) || profiles[0]).id;
      $$('[data-n]', root).forEach(el => countUp(el, +el.dataset.n));

      function renderList() {
        const L = profiles.filter(p => f === 'all' || (f === 'hi' && p.score >= 80) || (f === 'watch' && watch.has(p.name)) || (f === 'leave' && p.leaving));
        q('#ulist').innerHTML = L.length ? L.map((p, i) => { const lv = level(p.score); return `<li class="ub ${p.id === cur ? 'on' : ''}" data-id="${p.id}" style="--i:${i}">
          <span class="ub-rank ${i < 3 && f === 'all' ? 'top' : ''}">${i + 1}</span>${avatar(p.name, 'sm')}
          <div class="ub-m"><b>${esc(p.name)}${watch.has(p.name) ? ic('eye', 'ub-w') : ''}</b><small>${p.dept} · ${esc(p.title)}</small></div>
          <div class="ub-s"><b class="t-${lv[1]}">${p.score}</b><small class="${p.delta > 0 ? 'up' : 'down'}">${ic(p.delta > 0 ? 'trend-up' : 'trend-down')}${Math.abs(p.delta)}</small></div>
          <i class="ub-bar" style="--w:${p.score}%;--c:var(--${lv[1]})"></i></li>`; }).join('') : `<li class="empty-st">${ic('user')}<p>暂无用户</p></li>`;
      }
      function renderProfile() {
        charts.forEach(c => c.destroy && c.destroy()); charts = [];
        const p = profiles.find(x => x.id === cur), lv = level(p.score), an = anomalies(p);
        const inc = p.inc.slice(0, 5);
        const C0 = 2 * Math.PI * 52;
        q('#prof').innerHTML = `
          <section class="card ub-head">
            <div class="ub-id">${avatar(p.name, 'xl')}
              <div><h2>${esc(p.name)} <span class="tag b-${lv[1]}">${lv[0]}</span></h2>
                <p>${esc(p.dept)} · ${esc(p.title)}${p.fromDir ? ' · 工号 ' + esc(p.id) : ''}</p>
                <div class="ub-tags">${p.leaving ? `<span class="tag b-danger">${ic('logout')}离职流程中</span>` : ''}${watch.has(p.name) ? `<span class="tag b-primary">${ic('eye')}观察名单</span>` : ''}<span class="tag">${ic('monitor')}${p.host}</span><span class="tag">${ic('globe')}${p.ip}</span>${p.fromDir ? `<span class="tag">${ic('user-check')}组织架构</span>` : '<span class="tag b-warning">未在组织架构中</span>'}</div>
              </div></div>
            <div class="ub-ring">
              <svg viewBox="0 0 120 120"><circle class="rg-t" cx="60" cy="60" r="52"/><circle class="rg-v" cx="60" cy="60" r="52" style="stroke:var(--${lv[1]});stroke-dasharray:${C0.toFixed(1)};stroke-dashoffset:${C0.toFixed(1)}" data-off="${(C0 * (1 - p.score / 100)).toFixed(1)}"/></svg>
              <div><b id="scoreN">0</b><span>风险评分</span></div></div>
            <div class="ub-act">
              <button class="btn" data-a="watch" data-perm="ueba:op">${ic('eye')}<span>${watch.has(p.name) ? '移出观察名单' : '加入观察名单'}</span></button>
              <button class="btn" data-a="lvl" data-perm="ueba:op">${ic('shield')}提升管控等级</button>
            </div>
          </section>
          <div class="grid g2">
            ${card('行为维度分析', '<div id="radar"></div>', { sub: '与所在部门平均水平对比' })}
            ${card('风险评分趋势', '<div id="utrend" class="chart-box"></div>', { sub: '近 30 天', extra: `<span class="delta ${p.delta > 0 ? 'bad' : 'good'}">${ic(p.delta > 0 ? 'trend-up' : 'trend-down')}近 7 天 ${p.delta > 0 ? '+' : ''}${p.delta}</span>` })}
          </div>
          <div class="grid g2">
            ${card('异常行为', !an.length ? `<div class="empty-st">${ic('shield-check')}<p>未发现异常行为</p></div>` : `<ol class="anom">${an.map((a, i) => `<li style="--i:${i}"><span class="an-ic sev-${a.sev}">${ic(a.icon)}</span><div><b>${a.title}</b><p>${esc(a.text)}</p><time>${fmtTime(a.ts)} · ${relTime(a.ts)}</time></div><em class="t-${a.sev === 'critical' || a.sev === 'high' ? 'danger' : 'warning'}">+${a.add}</em></li>`).join('')}</ol>`, { sub: `识别出 ${an.length} 项风险行为`, extra: '<span class="muted small">分值为对风险评分的贡献</span>' })}
            ${card('关联事件', inc.length ? `<ul class="mini-list">${inc.map(i => `<li data-inc="${i.id}">${sevBadge(i.severity)}<span>${esc(i.file)}</span>${chIcon(i.channel)}${actBadge(i.action)}</li>`).join('')}</ul>` : `<div class="empty-st">${ic('shield-check')}<p>近 30 天无关联事件</p></div>`, { sub: `共 ${p.inc.length} 起 DLP 事件`, extra: UI.can('incidents') ? `<a class="link" href="#/incidents">查看全部</a>` : '' })}
          </div>`;
        requestAnimationFrame(() => requestAnimationFrame(() => { const rg = q('.rg-v'); if (rg) rg.style.strokeDashoffset = rg.dataset.off; }));
        countUp(q('#scoreN'), p.score, { from: 0, dur: 1200 });
        radar(q('#radar'), p);
        const days = p.trend.map((_, d) => { const t = new Date(Date.now() - (29 - d) * 864e5); return `${t.getMonth() + 1}/${t.getDate()}`; });
        charts.push(C.line(q('#utrend'), { height: 262, labels: days, series: [{ name: '风险评分', data: p.trend, color: lv[1] === 'success' ? 'c2' : lv[1] === 'primary' ? 'c1' : 'sev-high' }, { name: '部门平均', data: p.trend.map((_, d) => { const ps = profiles.filter(x => x.dept === p.dept); return Math.round(ps.reduce((s2, x) => s2 + x.trend[d], 0) / ps.length); }), color: 'c6', dash: true, area: false }] }));
        q('#prof').classList.remove('swap'); void q('#prof').offsetWidth; q('#prof').classList.add('swap'); UI.applyPerms(q('#prof'));
      }
      UI.onCleanup(() => charts.forEach(c => c.destroy && c.destroy()));

      initSeg(root, 'uf', v => { f = v; renderList(); });
      q('#ulist').addEventListener('click', e => {
        const li = e.target.closest('.ub'); if (!li || li.dataset.id === cur) return;
        cur = li.dataset.id; $$('.ub', root).forEach(x => x.classList.toggle('on', x.dataset.id === cur));
        renderProfile();
        if (innerWidth <= 1120) q('#prof').scrollIntoView({ behavior: 'smooth', block: 'start' });
      });
      q('#prof').addEventListener('click', async e => {
        const p = profiles.find(x => x.id === cur);
        const li = e.target.closest('[data-inc]');
        if (li) { UI.openIncident(li.dataset.inc); return; }
        const b = e.target.closest('[data-a]'); if (!b) return;
        if (b.dataset.a === 'watch') {
          const on = !watch.has(p.name);
          act(b, () => API.post('/ueba/watch', { user: p.name, on }), r => {
            D.watchlist = r.watchlist; watch.clear(); r.watchlist.forEach(n => watch.add(n));
            q('#wCnt').textContent = watch.size;
            toast(on ? `${esc(p.name)} 已加入观察名单，其后续事件不论级别都会立即通过已开启的告警通道通知` : `${esc(p.name)} 已移出观察名单`, { type: 'info' });
            renderList(); renderProfile();
          });
        } else if (b.dataset.a === 'lvl') {
          const ok = await confirmDialog({ title: `提升 ${esc(p.name)} 的管控等级`, text: '该用户使用的终端将启用严格管控：终端 Agent 把「仅审计」策略按阻断处理，未命中策略但含敏感内容的文件也会生成事件。该操作将记录到审计日志。', okText: '确认提升' });
          if (ok) act(b, () => API.post('/ueba/strict', { user: p.name }), r => toast(r.hosts.length ? `已对 ${esc(p.name)} 的终端（${r.hosts.map(esc).join('、')}）启用严格管控，Agent 将在下次心跳时同步` : `${esc(p.name)} 名下暂无已接入的终端，未下发严格管控`, { type: r.hosts.length ? 'success' : 'warning', title: '管控等级' }));
        }
      });
      q('#exp').addEventListener('click', () => UI.task(() => API.post('/exports', { kind: 'incidents', filter: { sev: 'critical' } })));
      renderList(); renderProfile();
    }
  };
})();
