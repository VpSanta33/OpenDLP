/* 安全态势总览 */
(function () {
  'use strict';
  const { D, C, ic, $$, fmt, esc, pad2, fmtTime, relTime, avatar, countUp, toast, seg, initSeg, card, sevBadge, actBadge, onCleanup, SEV, ACT, reduceMotion } = UI;

  const KPIS = [
    { key: 'events', label: '外发检测总数', icon: 'shield', color: 'c1', tone: 'primary', upGood: false },
    { key: 'blocked', label: '已阻断外发', icon: 'ban', color: 'c5', tone: 'danger', upGood: true },
    { key: 'pending', label: '高危待处置', icon: 'alert', color: 'c3', tone: 'warning', upGood: false },
    { key: 'online', label: '在线终端', icon: 'monitor', color: 'c2', tone: 'success', upGood: true }
  ];
  const CH_COLOR = { email: 'c1', im: 'c4', usb: 'c5', cloud: 'c2', web: 'c3', print: 'c6' };

  const kpiHtml = k => `<div class="kpi tone-${k.tone}" data-kpi="${k.key}">
      <div class="kpi-top"><span class="kpi-label">${k.label}</span><span class="kpi-ic">${ic(k.icon)}</span></div>
      <span class="kpi-val"><span class="kpi-num">0</span>${k.suffix ? `<small>${k.suffix}</small>` : ''}</span>
      <div class="kpi-foot"><div class="kpi-d"></div><div class="spark"></div></div></div>`;

  function feedItem(i, fresh) {
    const ch = D.chMap[i.channel], dt = D.dtMap[i.dataType];
    return `<li class="feed-item${fresh ? ' fresh' : ''}" data-id="${i.id}">
      <span class="feed-sev sev-bar-${i.severity}"></span><span class="feed-ic">${ic(ch.icon)}</span>
      <div class="feed-main"><div class="feed-t"><b>${esc(i.user)}</b><span class="muted">通过${ch.name}外发</span><em>${esc(i.file)}</em></div>
      <div class="feed-m">${sevBadge(i.severity)}<span>${dt.name} · 命中 ${i.matches} 处</span><span class="mono">${i.host}</span></div></div>
      <div class="feed-r">${actBadge(i.action)}<time data-ts="${i.ts}">${relTime(i.ts)}</time></div></li>`;
  }

  function riskUsers() {
    const m = {};
    D.incidents.forEach(i => {
      const u = m[i.user] || (m[i.user] = { name: i.user, dept: i.dept, count: 0, critical: 0, pts: 0 });
      u.count++; if (i.severity === 'critical') u.critical++; u.pts += SEV[i.severity].w;
    });
    const arr = Object.values(m).sort((a, b) => b.pts - a.pts).slice(0, 6);
    const max = arr[0] ? arr[0].pts : 1;
    arr.forEach((u, k) => { u.score = Math.min(99, Math.round(56 + 42 * u.pts / max - k)); });
    return arr;
  }

  /* ---------- 数据外发通道流向动画 ---------- */
  function mountFlow(el, statsEl) {
    const W = 760, H = 300, ex = 382, ey = 150, ox = 626;
    const chs = D.channels;
    const sy = i => 28 + i * (H - 56) / (chs.length - 1);
    const outs = [
      { key: 'allow', name: '放行', y: 62 },
      { key: 'audit', name: '审计 / 加密', y: 150 },
      { key: 'block', name: '阻断', y: 238 }
    ];
    let s = `<svg viewBox="0 0 ${W} ${H}" class="flow-svg" role="img" aria-label="数据外发通道流向">`;
    chs.forEach((c, i) => { s += `<path class="f-path p-in" d="M150,${sy(i)} C250,${sy(i)} 262,${ey} ${ex - 50},${ey}"/>`; });
    outs.forEach(o => { s += `<path class="f-path p-out f-${o.key}" d="M${ex + 50},${ey} C${ex + 130},${ey} ${ox - 120},${o.y} ${ox - 6},${o.y}"/>`; });
    chs.forEach((c, i) => {
      const y = sy(i);
      s += `<g class="f-node" data-n="${i}"><rect x="14" y="${y - 16}" width="136" height="32" rx="8"/><g transform="translate(25,${y - 8}) scale(.68)" class="fi">${ICONS[c.icon]}</g><text x="50" y="${y + 4.5}">${c.name}</text></g>`;
    });
    s += `<g class="engine"><circle class="eng-pulse" cx="${ex}" cy="${ey}" r="48"/><circle class="eng-glow" cx="${ex}" cy="${ey}" r="48"/>
      <circle class="eng-ring" cx="${ex}" cy="${ey}" r="56"/><circle class="eng-ring r2" cx="${ex}" cy="${ey}" r="64"/>
      <circle class="eng-core" cx="${ex}" cy="${ey}" r="34"/><g transform="translate(${ex - 11},${ey - 22}) scale(.92)" class="eng-ic">${ICONS['shield-check']}</g>
      <text x="${ex}" y="${ey + 17}" text-anchor="middle" class="eng-t">DLP 引擎</text></g>`;
    outs.forEach((o, i) => {
      s += `<g class="f-out f-${o.key}" data-o="${i}"><rect x="${ox - 6}" y="${o.y - 22}" width="130" height="44" rx="10"/><circle cx="${ox + 12}" cy="${o.y}" r="5" class="f-out-dot"/>
        <text x="${ox + 26}" y="${o.y - 4}" class="f-out-n">${o.name}</text><text x="${ox + 26}" y="${o.y + 14}" class="f-out-c" data-oc="${i}">0</text></g>`;
    });
    s += '<g class="pts"></g></svg>';
    el.innerHTML = s;

    const NS = 'http://www.w3.org/2000/svg';
    const svg = el.querySelector('svg'), g = svg.querySelector('.pts');
    const pIn = Array.from(svg.querySelectorAll('.p-in')), pOut = Array.from(svg.querySelectorAll('.p-out'));
    const lIn = pIn.map(p => p.getTotalLength()), lOut = pOut.map(p => p.getTotalLength());
    const nodes = Array.from(svg.querySelectorAll('.f-node')), outG = Array.from(svg.querySelectorAll('.f-out'));
    const cntEls = Array.from(svg.querySelectorAll('[data-oc]'));
    // 计数来自服务端「今日」统计；实时事件到达时沿真实渠道与处置结果流动一个粒子并计数。
    // 有数据时另有少量装饰性粒子（不计数），无数据时画面静止。
    let counts = [0, 0, 0], rules = 0, ambient = false;
    const total = () => counts.reduce((a, b) => a + b, 0);
    const updStats = () => {
      const t = total();
      statsEl.innerHTML = `<span>今日检测<b>${fmt(t)}</b></span><span>阻断率<b>${t ? (counts[2] / t * 100).toFixed(1) + '%' : '-'}</b></span><span>审计 / 加密<b>${fmt(counts[1])}</b></span><span>启用识别规则<b>${fmt(rules)} 条</b></span>`;
    };
    updStats();

    const parts = [];
    let last = performance.now(), acc = 0, raf = 0;
    const ease = t => t < .5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    function spawn(idx, outcome, real) {
      const c = document.createElementNS(NS, 'circle');
      c.setAttribute('r', real ? '4' : '3'); c.setAttribute('class', 'pt' + (real ? ' pt-real' : ''));
      const p0 = pIn[idx].getPointAtLength(0); c.setAttribute('cx', p0.x); c.setAttribute('cy', p0.y);
      g.appendChild(c);
      parts.push({ el: c, stage: 0, idx, outcome, real, t: 0, speed: 0.42 + Math.random() * 0.3 });
      nodes[idx].classList.add('hit'); setTimeout(() => nodes[idx].classList.remove('hit'), 260);
    }
    function tick(now) {
      const dt = Math.min(50, now - last) / 1000; last = now; acc += dt;
      if (ambient && acc > (reduceMotion ? 2 : 0.45)) {
        acc = 0;
        if (parts.length < 40) { const r = Math.random() * total(); spawn(Math.floor(Math.random() * chs.length), r < counts[0] ? 0 : r < counts[0] + counts[1] ? 1 : 2, false); }
      }
      for (let k = parts.length - 1; k >= 0; k--) {
        const p = parts[k];
        p.t += dt * p.speed;
        if (p.t >= 1) {
          if (p.stage === 0) {
            p.stage = 1; p.t = 0; p.idx = p.outcome;
            p.el.setAttribute('class', 'pt pt-' + outs[p.idx].key + (p.real ? ' pt-real' : ''));
          } else {
            if (p.real) {
              counts[p.idx]++;
              cntEls[p.idx].textContent = fmt(counts[p.idx]); cntEls[p.idx].dataset.v = counts[p.idx];
              const og = outG[p.idx]; og.classList.remove('flash'); requestAnimationFrame(() => og.classList.add('flash'));
              updStats();
            }
            p.el.remove(); parts.splice(k, 1);
            continue;
          }
        }
        const path = p.stage === 0 ? pIn[p.idx] : pOut[p.idx];
        const L = p.stage === 0 ? lIn[p.idx] : lOut[p.idx];
        const pt = path.getPointAtLength(ease(p.t) * L);
        p.el.setAttribute('cx', pt.x.toFixed(1)); p.el.setAttribute('cy', pt.y.toFixed(1));
      }
      raf = requestAnimationFrame(tick);
    }
    raf = requestAnimationFrame(tick);
    return {
      destroy() { cancelAnimationFrame(raf); },
      setFlow(f) {
        counts = [f.allow, f.audit, f.block]; rules = f.rules; ambient = f.total > 0;
        cntEls.forEach((c, i) => countUp(c, counts[i], { from: 0 }));
        updStats();
      },
      event(inc) {
        const idx = chs.findIndex(c => c.key === inc.channel);
        if (idx >= 0) spawn(idx, inc.action === 'block' ? 2 : inc.action === 'allow' ? 0 : 1, true);
      }
    };
  }

  UI.pages.dashboard = {
    title: '安全态势总览', icon: 'dashboard',
    html() {
      const lg = [['c1', '告警事件'], ['c5', '阻断事件'], ['c6', '上一周期', true]].map(([c, n, d]) => `<span><i class="${d ? 'dash' : ''}" style="background:var(--${c})"></i>${n}</span>`).join('');
      const heatLg = `<div class="heat-lg">少<i style="--v:.1"></i><i style="--v:.3"></i><i style="--v:.55"></i><i style="--v:.8"></i><i style="--v:1"></i>多</div>`;
      return `
      <div class="page-head">
        <div><h1>安全态势总览</h1><p>外发检测、阻断与事件概况 · 数据更新于 <span id="lastUpd">${fmtTime(Date.now(), false)}</span></p></div>
        <div class="head-actions">${seg('range', [['today', '今日'], ['7d', '近 7 天'], ['30d', '近 30 天']], '30d')}
          <button class="btn" data-act="export">${ic('download')}导出报告</button></div>
      </div>
      <div class="callout empty-banner" id="emptyBanner" hidden>${ic('activity')}<div><b>尚未接收到检测数据。</b>请在终端与网关部署 OpenDLP Agent，并配置上报令牌（OPENDLP_AGENT_TOKEN）。数据上报后这里将实时展示外发检测态势。${UI.can('endpoints') ? ' <a href="#/endpoints">查看终端接入方式</a>' : ''}</div></div>
      <div class="kpis">${KPIS.map(kpiHtml).join('')}</div>
      <div class="grid">
        ${card('综合风险指数', `<div id="gauge" class="gauge-wrap"></div><ul class="factors" id="factors"></ul>`, { sub: '近 30 天：高危占比、离职人员外发、U 盘未阻断与策略启用率加权计算', extra: '<span class="tag" id="riskTag">计算中</span>' })}
        ${card('数据外发通道实时监测', '<div id="flow" class="flow"></div><div class="flow-stats" id="flowStats"></div>', { cls: 'span-2', sub: '今日上报的检测按处置结果统计（连线动画仅为示意）', extra: '<span class="live"><i></i>LIVE</span>' })}
      </div>
      <div class="grid">
        ${card('事件趋势', '<div id="trend" class="chart-box"></div>', { cls: 'span-2', sub: '告警与阻断事件走势，悬停查看明细', extra: `<div class="lg">${lg}</div>` })}
        ${card('外发通道分布', '<div id="donut"></div>', { sub: '按外发渠道统计告警事件' })}
      </div>
      <div class="grid">
        ${card('实时事件流', '<ul class="feed" id="feed"></ul>', { cls: 'span-2', sub: '最新检测到的数据外发行为，点击查看详情', extra: `<span class="live" id="feedLive"><i></i>实时</span><button class="btn btn-sm" id="feedToggle">${ic('pause')}<span>暂停</span></button><a class="btn btn-sm btn-ghost" href="#/incidents">全部事件${ic('chevron-right')}</a>` })}
        ${card('高风险用户 TOP 6', '<ul class="ru" id="riskUsers"></ul>', { sub: '基于 UEBA 行为基线的风险评分' })}
      </div>
      <div class="grid">
        ${card('敏感数据类型命中', '<div id="dtBars" class="bars"></div>', { sub: '按识别出的数据分类统计' })}
        ${card('事件时段分布', '<div id="heat"></div><div class="heat-note"><i></i>红色格子表示非工作时段的异常外发高峰</div>', { cls: 'span-2', sub: '近 7 天 · 按星期与小时聚合', extra: heatLg })}
      </div>`;
    },
    mount(root) {
      let range = '30d', paused = false, lastToast = 0, db = null, trend = null;
      const vals = {};
      const q = s => root.querySelector(s);

      function renderKpis() {
        const k = db.kpi;
        KPIS.forEach(def => {
          const el = q(`[data-kpi="${def.key}"]`);
          const v = def.key === 'pending' ? UI.pendingHigh() : k[def.key];
          vals[def.key] = v;
          countUp(el.querySelector('.kpi-num'), v);
          if (def.key === 'online') {
            if (!el.querySelector('.kpi-val small')) el.querySelector('.kpi-val').insertAdjacentHTML('beforeend', '<small></small>');
            el.querySelector('.kpi-val small').textContent = `/ ${fmt(k.deployed)}`;
            el.querySelector('.kpi-d').innerHTML = `<span class="delta good">${(k.online / Math.max(1, k.deployed) * 100).toFixed(1)}%</span><span class="vs">在线率</span>`;
            return;
          }
          const d = k.delta[def.key];
          el.querySelector('.kpi-d').innerHTML = d == null ? '<span class="vs">无上周期数据</span>'
            : `<span class="delta ${(d >= 0) === def.upGood ? 'good' : 'bad'}">${ic(d >= 0 ? 'trend-up' : 'trend-down')}${Math.abs(d)}%</span><span class="vs">较上周期</span>`;
          if (k.sparks[def.key]) C.spark(el.querySelector('.spark'), k.sparks[def.key], def.color);
        });
      }
      function setKpi(key, v) {
        vals[key] = v;
        const el = q(`[data-kpi="${key}"]`); if (!el) return;
        const n = el.querySelector('.kpi-num'); n.dataset.v = v; n.textContent = fmt(v);
        el.classList.remove('bump'); void el.offsetWidth; el.classList.add('bump');
      }
      const trendData = () => ({
        labels: db.labels,
        tipTitle: l => range === 'today' ? `今日 ${l}` : `${new Date(D.NOW).getFullYear()}/${l}`,
        series: [
          { name: '外发检测', color: 'c1', data: db.alerts },
          { name: '阻断外发', color: 'c5', data: db.blocked },
          { name: '上一周期', color: 'c6', data: db.prev, dash: true, area: false }
        ]
      });
      const renderDonut = () => C.donut(q('#donut'), {
        label: '外发检测',
        items: db.channels.map(c => ({ name: D.chMap[c.key].name, value: c.value, color: CH_COLOR[c.key] })).sort((a, b) => b.value - a.value)
      });
      const renderBars = () => C.bars(q('#dtBars'), db.dataTypes.slice().sort((a, b) => b.value - a.value)
        .map((d, i) => ({ name: D.dtMap[d.key].name, value: d.value, color: i < 2 ? 'c5' : i < 4 ? 'c3' : 'c1' })));
      function renderRisk() {
        const r = db.risk;
        C.gauge(q('#gauge'), r.score, { label: r.level === '暂无数据' ? '暂无数据' : '风险指数 · 近 30 天' });
        q('#riskTag').className = 'tag b-' + r.tone; q('#riskTag').textContent = r.level;
        q('#factors').innerHTML = r.factors.map(f => `<li><span>${f.name}</span><div class="meter"><i class="${f.tone}" style="--w:${f.pct}%"></i></div><b>${f.label}</b></li>`).join('');
      }
      async function load(first) {
        try { db = await API.get('/dashboard?range=' + range); } catch (e) { UI.apiError(e); return; }
        if (!root.isConnected) return;
        renderKpis(); renderDonut(); renderBars();
        flow.setFlow(db.flow);
        const banner = q('#emptyBanner');
        if (banner) banner.hidden = !db.empty;
        if (first) {
          renderRisk();
          trend = C.line(q('#trend'), Object.assign({ height: 290 }, trendData()));
          onCleanup(() => trend.destroy());
          C.heatmap(q('#heat'), db.heatmap, ['周一', '周二', '周三', '周四', '周五', '周六', '周日']);
        } else trend.update(trendData());
      }
      const flow = mountFlow(q('#flow'), q('#flowStats'));
      onCleanup(() => flow.destroy());
      load(true);
      const ru = riskUsers();

      q('#riskUsers').innerHTML = !ru.length ? `<li class="empty-st">${ic('shield-check')}<p>近 30 天无风险用户</p></li>` : ru.map((u, k) => `<li style="--i:${k}"><span class="rank">${k + 1}</span>${avatar(u.name)}
        <div class="ru-main"><div class="ru-top"><b>${esc(u.name)}</b><small>${u.dept}</small><em>${u.score}</em></div>
        <div class="meter"><i class="${u.score >= 85 ? 'hot' : u.score >= 70 ? 'warm' : ''}" style="--w:${u.score}%;--d:${0.3 + k * 0.08}s"></i></div>
        <small class="muted">${u.count} 起事件 · ${u.critical} 起严重</small></div></li>`).join('');

      initSeg(root, 'range', v => { range = v; load(false); });

      q('[data-act="export"]').addEventListener('click', e => {
        if (!UI.canDo('reports', 'exp')) { toast('当前角色无报表导出权限', { type: 'warning', title: '无权限' }); return; }
        UI.task(() => API.post('/reports', { tpl: 'exec', range: 'lm', fmt: 'HTML' }));
      });

      /* 实时事件流 */
      const feed = q('#feed');
      feed.innerHTML = D.incidents.length ? D.incidents.slice(0, 7).map(i => feedItem(i)).join('') : `<li class="empty-st">${ic('activity')}<p>等待终端 / 网关上报检测数据</p></li>`;
      feed.addEventListener('click', e => {
        const li = e.target.closest('.feed-item');
        if (li) UI.openIncident(li.dataset.id, () => setKpi('pending', UI.pendingHigh()));
      });
      const btn = q('#feedToggle');
      btn.addEventListener('click', () => {
        paused = !paused;
        btn.innerHTML = paused ? `${ic('play')}<span>继续</span>` : `${ic('pause')}<span>暂停</span>`;
        q('#feedLive').classList.toggle('paused', paused);
        q('#feedLive').lastChild.textContent = paused ? '已暂停' : '实时';
      });
      // 实时事件由服务端 SSE 推送（终端 / 网关上报；开发模式下为模拟器）
      UI.listen('incident', inc => {
        flow.event(inc);
        const banner = q('#emptyBanner'); if (banner) banner.hidden = true;
        if (feed.querySelector('.empty-st')) feed.innerHTML = '';
        if (paused) return;
        feed.insertAdjacentHTML('afterbegin', feedItem(inc, true));
        while (feed.children.length > 7) feed.lastElementChild.remove();
        if (vals.events != null) setKpi('events', vals.events + 1);
        if (inc.action === 'block' && vals.blocked != null) setKpi('blocked', vals.blocked + 1);
        if (inc.severity === 'critical' || inc.severity === 'high') setKpi('pending', UI.pendingHigh());
        if (inc.severity === 'critical' && Date.now() - lastToast > 20000) {
          lastToast = Date.now();
          toast(`${esc(inc.user)}${inc.dept ? '（' + esc(inc.dept) + '）' : ''}尝试通过${D.chMap[inc.channel].name}外发「${esc(inc.file)}」 · ${ACT[inc.action].name}`, { type: 'error', title: '检测到严重事件' });
        }
        q('#lastUpd').textContent = fmtTime(Date.now(), false);
      });
      UI.listen('fleet', f => {
        if (!db) return;
        db.kpi.online = f.online; db.kpi.deployed = f.deployed;
        const el = q('[data-kpi="online"]'); if (!el) return;
        el.querySelector('.kpi-num').textContent = fmt(f.online);
        const sm = el.querySelector('.kpi-val small'); if (sm) sm.textContent = `/ ${fmt(f.deployed)}`;
        el.querySelector('.kpi-d').innerHTML = `<span class="delta good">${(f.online / Math.max(1, f.deployed) * 100).toFixed(1)}%</span><span class="vs">在线率</span>`;
      });
      const timer = setInterval(() => $$('time[data-ts]', feed).forEach(t => { t.textContent = relTime(+t.dataset.ts); }), 15000);
      onCleanup(() => clearInterval(timer));
    }
  };
})();
