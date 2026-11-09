/* ==========================================================================
   轻量 SVG 图表库（零依赖）：折线 / 环形 / 仪表盘 / 迷你图 / 条形 / 热力图
   颜色全部引用 CSS 变量，主题切换时自动适配
   ========================================================================== */
(function () {
  'use strict';
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const fmt = n => Number(n).toLocaleString('zh-CN');
  const fmtShort = v => {
    if (v >= 10000) return (v / 10000).toFixed(1).replace(/\.0$/, '') + '万';
    if (v >= 1000) return (v / 1000).toFixed(1).replace(/\.0$/, '') + 'k';
    return String(Math.round(v));
  };
  const debounce = (fn, ms) => { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; };
  const nextFrame = fn => requestAnimationFrame(() => requestAnimationFrame(fn));

  function countUp(el, to, opt) {
    if (!el) return;
    const o = opt || {};
    const from = o.from != null ? o.from : (parseFloat(el.dataset.v) || 0);
    const dur = o.dur || 1200;
    el.dataset.v = to;
    if (reduceMotion || from === to) { el.textContent = fmt(to); return; }
    const t0 = performance.now();
    const step = now => {
      if (el.dataset.v != String(to)) return; // 已被新的目标值覆盖
      const p = Math.min(1, (now - t0) / dur);
      const e = 1 - Math.pow(1 - p, 3);
      el.textContent = fmt(Math.round(from + (to - from) * e));
      if (p < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function smoothPath(pts) {
    if (!pts.length) return '';
    let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
    for (let i = 0; i < pts.length - 1; i++) {
      const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
      const t = 0.18;
      const c1x = p1[0] + (p2[0] - p0[0]) * t, c1y = p1[1] + (p2[1] - p0[1]) * t;
      const c2x = p2[0] - (p3[0] - p1[0]) * t, c2y = p2[1] - (p3[1] - p1[1]) * t;
      d += ` C${c1x.toFixed(1)},${c1y.toFixed(1)} ${c2x.toFixed(1)},${c2y.toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
    }
    return d;
  }
  function niceMax(v) {
    if (v <= 0) return 1;
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    const n = v / p;
    return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * p;
  }

  /* ---------- 折线面积图 ---------- */
  function line(el, opt) {
    let lastW = 0;
    const uid = 'ln' + Math.random().toString(36).slice(2, 8);
    function render(animate) {
      const W = Math.max(280, el.clientWidth || 600), H = opt.height || 260;
      lastW = W;
      const pad = { l: 44, r: 12, t: 14, b: 28 };
      const iw = W - pad.l - pad.r, ih = H - pad.t - pad.b;
      const n = opt.labels.length;
      const max = niceMax(Math.max(...opt.series.flatMap(s => s.data)) * 1.08);
      const x = i => pad.l + (n === 1 ? iw / 2 : i * iw / (n - 1));
      const y = v => pad.t + ih - v / max * ih;

      let g = '';
      for (let i = 0; i <= 4; i++) {
        const v = max * i / 4, yy = y(v).toFixed(1);
        g += `<line class="gl" x1="${pad.l}" x2="${W - pad.r}" y1="${yy}" y2="${yy}"/><text class="axis" x="${pad.l - 8}" y="${+yy + 4}" text-anchor="end">${fmtShort(v)}</text>`;
      }
      const step = Math.max(1, Math.ceil(n / Math.max(2, Math.floor(iw / 64))));
      opt.labels.forEach((l, i) => { if (i % step === 0) g += `<text class="axis" x="${x(i).toFixed(1)}" y="${H - 8}" text-anchor="middle">${l}</text>`; });

      let defs = '<defs>', paths = '';
      opt.series.forEach((s, si) => {
        const pts = s.data.map((v, i) => [x(i), y(v)]);
        const d = smoothPath(pts);
        if (s.area !== false) {
          defs += `<linearGradient id="${uid}${si}" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" style="stop-color:var(--${s.color});stop-opacity:.22"/><stop offset="100%" style="stop-color:var(--${s.color});stop-opacity:0"/></linearGradient>`;
          paths += `<path class="${animate ? 'anim-fade' : ''}" d="${d} L${x(n - 1).toFixed(1)},${pad.t + ih} L${x(0).toFixed(1)},${pad.t + ih} Z" fill="url(#${uid}${si})"/>`;
        }
        const cls = s.dash ? 'line dash' + (animate ? ' anim-fade' : '') : 'line' + (animate ? ' anim-draw' : '');
        // 虚线系列不设置 pathLength，避免与 dasharray 冲突
        paths += `<path class="${cls}"${s.dash ? '' : ' pathLength="1"'} d="${d}" style="stroke:var(--${s.color})"/>`;
      });
      defs += '</defs>';

      el.innerHTML = `<svg class="chart" viewBox="0 0 ${W} ${H}" width="100%" height="${H}">${defs}${g}${paths}
        <line class="xhair" y1="${pad.t}" y2="${pad.t + ih}" x1="0" x2="0"/>
        ${opt.series.map(s => `<circle class="hdot" r="4.5" cx="-10" cy="-10" style="stroke:var(--${s.color})"/>`).join('')}
        <rect class="hit" x="${pad.l}" y="${pad.t}" width="${iw}" height="${ih}" fill="transparent"/></svg><div class="tip"></div>`;

      const svg = el.querySelector('svg'), hit = svg.querySelector('.hit'), xh = svg.querySelector('.xhair');
      const dots = Array.from(svg.querySelectorAll('.hdot')), tip = el.querySelector('.tip');
      const move = e => {
        const r = svg.getBoundingClientRect();
        const mx = (e.clientX - r.left) * (W / r.width);
        let i = Math.round((mx - pad.l) / iw * (n - 1));
        i = Math.max(0, Math.min(n - 1, i));
        const xx = x(i);
        xh.setAttribute('x1', xx); xh.setAttribute('x2', xx);
        svg.classList.add('hovering');
        dots.forEach((dt, si) => { dt.setAttribute('cx', xx); dt.setAttribute('cy', y(opt.series[si].data[i])); });
        tip.innerHTML = `<div class="tip-t">${opt.tipTitle ? opt.tipTitle(opt.labels[i]) : opt.labels[i]}</div>` +
          opt.series.map(s => `<div class="tip-r"><i style="background:var(--${s.color})"></i>${s.name}<b>${fmt(s.data[i])}</b></div>`).join('');
        const px = xx / W * r.width;
        tip.style.left = px + 'px';
        tip.style.top = (pad.t + 6) + 'px';
        tip.classList.toggle('flip', px > r.width * 0.62);
        tip.classList.add('show');
      };
      hit.addEventListener('mousemove', move);
      hit.addEventListener('mouseleave', () => { svg.classList.remove('hovering'); tip.classList.remove('show'); });
    }
    render(true);
    const ro = new ResizeObserver(debounce(() => { if (Math.abs(el.clientWidth - lastW) > 4) render(false); }, 150));
    ro.observe(el);
    return { update(o) { Object.assign(opt, o); render(true); }, destroy() { ro.disconnect(); } };
  }

  /* ---------- 环形图 ---------- */
  function donut(el, opt) {
    const total = opt.items.reduce((s, i) => s + i.value, 0) || 1;
    const R = 66, Cf = 2 * Math.PI * R;
    let off = 0;
    const segs = opt.items.map((it, i) => { const len = it.value / total * Cf; const s = { ...it, len, off, i }; off += len; return s; });
    el.innerHTML = `<div class="donut-wrap"><div class="donut"><svg viewBox="0 0 180 180"><circle class="donut-track" cx="90" cy="90" r="${R}"/>${segs.map(s =>
      `<circle class="donut-seg" data-i="${s.i}" cx="90" cy="90" r="${R}" style="stroke:var(--${s.color});stroke-dasharray:0 ${Cf.toFixed(1)};stroke-dashoffset:${(-s.off).toFixed(1)}" data-dash="${Math.max(0, s.len - 2.5).toFixed(1)} ${Cf.toFixed(1)}"/>`).join('')}</svg>
      <div class="donut-center"><b data-v="0">0</b><span>${opt.label || '合计'}</span></div></div>
      <ul class="legend">${segs.map(s => `<li data-i="${s.i}"><i style="background:var(--${s.color})"></i>${s.name}<b>${fmt(s.value)}</b><em>${(s.value / total * 100).toFixed(1)}%</em></li>`).join('')}</ul></div>`;

    const wrap = el.querySelector('.donut-wrap'), cb = el.querySelector('.donut-center b'), cs = el.querySelector('.donut-center span');
    const circles = Array.from(el.querySelectorAll('.donut-seg')), lis = Array.from(el.querySelectorAll('.legend li'));
    nextFrame(() => {
      circles.forEach((c, i) => { c.style.transitionDelay = (i * 90) + 'ms'; c.style.strokeDasharray = c.dataset.dash; });
      setTimeout(() => circles.forEach(c => { c.style.transitionDelay = '0ms'; }), 1200 + circles.length * 90);
    });
    countUp(cb, total, { from: 0 });
    const on = i => {
      wrap.classList.toggle('has-hover', i != null);
      circles.forEach(c => c.classList.toggle('on', +c.dataset.i === i));
      lis.forEach(l => l.classList.toggle('on', +l.dataset.i === i));
      if (i == null) { cb.textContent = fmt(total); cs.textContent = opt.label || '合计'; }
      else { cb.textContent = (segs[i].value / total * 100).toFixed(1) + '%'; cs.textContent = segs[i].name; }
    };
    circles.concat(lis).forEach(n => {
      n.addEventListener('mouseenter', () => on(+n.dataset.i));
      n.addEventListener('mouseleave', () => on(null));
    });
  }

  /* ---------- 半圆仪表盘 ---------- */
  function gauge(el, value, opt) {
    const o = opt || {};
    const R = 80, Cf = Math.PI * R;
    let ticks = '';
    for (let k = 0; k <= 10; k++) {
      const a = Math.PI - k / 10 * Math.PI, r1 = k % 5 === 0 ? 55 : 59, r2 = 64;
      ticks += `<line class="gauge-tick" x1="${(100 + Math.cos(a) * r1).toFixed(1)}" y1="${(100 - Math.sin(a) * r1).toFixed(1)}" x2="${(100 + Math.cos(a) * r2).toFixed(1)}" y2="${(100 - Math.sin(a) * r2).toFixed(1)}"/>`;
    }
    el.innerHTML = `<svg viewBox="0 0 200 110" class="gauge">
      <defs><linearGradient id="gaugeGrad" x1="0" x2="1" y1="0" y2="0"><stop offset="0" style="stop-color:var(--success)"/><stop offset=".5" style="stop-color:var(--warning)"/><stop offset="1" style="stop-color:var(--danger)"/></linearGradient></defs>
      <path class="gauge-track" d="M20,100 A80,80 0 0 1 180,100"/>
      <path class="gauge-val" d="M20,100 A80,80 0 0 1 180,100" style="stroke:url(#gaugeGrad);stroke-dasharray:${Cf.toFixed(1)};stroke-dashoffset:${Cf.toFixed(1)}"/>
      ${ticks}
      <text x="22" y="109" class="axis" style="fill:var(--muted);font-size:9px" text-anchor="middle">0</text>
      <text x="178" y="109" class="axis" style="fill:var(--muted);font-size:9px" text-anchor="middle">100</text>
      <g class="needle" style="transform:rotate(-90deg)"><line x1="100" y1="100" x2="100" y2="42"/><circle cx="100" cy="100" r="6.5"/><circle class="needle-in" cx="100" cy="100" r="2.5"/></g>
    </svg><div class="gauge-num"><b>0</b><span>${o.label || ''}</span></div>`;
    const val = el.querySelector('.gauge-val'), nd = el.querySelector('.needle');
    nextFrame(() => {
      val.style.strokeDashoffset = (Cf * (1 - value / 100)).toFixed(1);
      nd.style.transform = `rotate(${-90 + 180 * value / 100}deg)`;
    });
    countUp(el.querySelector('.gauge-num b'), value, { dur: 1800, from: 0 });
  }

  /* ---------- 迷你折线 ---------- */
  function spark(el, data, color) {
    const W = 120, H = 38, max = Math.max(...data), min = Math.min(...data), span = (max - min) || 1;
    const pts = data.map((v, i) => [i * W / (data.length - 1), H - 4 - (v - min) / span * (H - 8)]);
    const d = smoothPath(pts);
    const gid = 'sp' + Math.random().toString(36).slice(2, 7);
    el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none"><defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" style="stop-color:var(--${color});stop-opacity:.25"/><stop offset="1" style="stop-color:var(--${color});stop-opacity:0"/></linearGradient></defs>
      <path class="anim-fade" d="${d} L${W},${H} L0,${H} Z" fill="url(#${gid})"/>
      <path class="anim-draw" pathLength="1" d="${d}" fill="none" style="stroke:var(--${color})" stroke-width="1.8" stroke-linecap="round"/>
      <circle cx="${pts[pts.length - 1][0]}" cy="${pts[pts.length - 1][1].toFixed(1)}" r="2.6" class="anim-fade" style="fill:var(--${color})"/></svg>`;
  }

  /* ---------- 横向条形 ---------- */
  function bars(el, items) {
    const max = Math.max(...items.map(i => i.value)) || 1;
    el.innerHTML = items.map((it, i) => `<div class="bar-row"><div class="bar-label">${it.name}</div><div class="bar-track"><div class="bar-fill" style="--w:${(it.value / max * 100).toFixed(1)}%;--d:${i * 70}ms;background:var(--${it.color || 'c1'})"></div></div><div class="bar-val">${fmt(it.value)}</div></div>`).join('');
  }

  /* ---------- 热力图 ---------- */
  function heatmap(el, matrix, rows) {
    const max = Math.max(...matrix.flat()) || 1;
    let html = '<div class="heat">';
    matrix.forEach((row, ri) => {
      html += `<div class="heat-label">${rows[ri]}</div>`;
      row.forEach((v, h) => {
        const night = (h >= 23 || h <= 5) && v > max * 0.3;
        html += `<div class="heat-cell${night ? ' night' : ''}" style="--v:${(0.07 + 0.93 * v / max).toFixed(2)};--d:${(h * 14 + ri * 22)}ms" data-tip="${rows[ri]} ${String(h).padStart(2, '0')}:00 · ${v} 起${night ? ' · 非工作时段异常' : ''}"></div>`;
      });
    });
    html += '<div></div>';
    for (let h = 0; h < 24; h++) html += `<div class="heat-h">${h % 3 === 0 ? h : ''}</div>`;
    el.innerHTML = html + '</div>';
  }

  window.Charts = { line, donut, gauge, spark, bars, heatmap, countUp, fmtShort };
})();
