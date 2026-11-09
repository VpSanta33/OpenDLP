/* ==========================================================================
   公共 UI 工具：格式化、徽标、Toast、抽屉/弹窗、分段控件、分页、页面生命周期
   ========================================================================== */
(function () {
  'use strict';
  const D = window.DLP, C = window.Charts, ic = window.ic;
  const $ = (s, r) => (r || document).querySelector(s);
  const $$ = (s, r) => Array.from((r || document).querySelectorAll(s));
  const fmt = n => Number(n).toLocaleString('zh-CN');
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const pad2 = n => String(n).padStart(2, '0');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function fmtTime(ts, withDate) {
    const d = new Date(ts);
    return (withDate === false ? '' : `${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} `) + `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }
  function relTime(ts) {
    const s = Math.max(0, (Date.now() - ts) / 1000);
    if (s < 45) return '刚刚';
    if (s < 3600) return Math.max(1, Math.round(s / 60)) + ' 分钟前';
    if (s < 86400) return Math.round(s / 3600) + ' 小时前';
    return Math.round(s / 86400) + ' 天前';
  }
  function hue(s) { let h = 7; for (const ch of String(s)) h = (h * 31 + ch.charCodeAt(0)) % 360; return h; }
  const avatar = (name, cls) => `<span class="av ${cls || ''}" style="background:hsl(${hue(name)} 55% 50%)">${esc(String(name)[0])}</span>`;

  const store = {
    get(k, d) { try { const v = localStorage.getItem('odlp.' + k); return v === null ? d : JSON.parse(v); } catch (e) { return d; } },
    set(k, v) { try { localStorage.setItem('odlp.' + k, JSON.stringify(v)); } catch (e) { /* ignore */ } }
  };

  /* ---------- 字典 ---------- */
  const SEV = { critical: { name: '严重', w: 4 }, high: { name: '高危', w: 3 }, medium: { name: '中危', w: 2 }, low: { name: '低危', w: 1 } };
  const ACT = {
    block: { name: '已阻断', cls: 'b-danger', icon: 'ban' },
    encrypt: { name: '加密放行', cls: 'b-info', icon: 'lock' },
    audit: { name: '仅审计', cls: 'b-warning', icon: 'eye' },
    allow: { name: '已放行', cls: 'b-success', icon: 'check' }
  };
  const ST = { pending: '待处置', processing: '处置中', resolved: '已处置', fp: '误报' };

  const sevBadge = s => `<span class="sev sev-${s}"><i></i>${SEV[s].name}</span>`;
  const actBadge = a => `<span class="tag ${ACT[a].cls}">${ic(ACT[a].icon)}${ACT[a].name}</span>`;
  const stBadge = s => `<span class="status st-${s}">${ST[s]}</span>`;
  const chIcon = k => { const c = D.chMap[k]; return `<span class="ch">${ic(c.icon)}${c.name}</span>`; };
  const pendingHigh = () => D.incidents.filter(i => i.status === 'pending' && (i.severity === 'critical' || i.severity === 'high')).length;

  /* ---------- 页面生命周期 ---------- */
  let cleanups = [];
  const onCleanup = fn => cleanups.push(fn);
  const runCleanups = () => { cleanups.forEach(f => { try { f(); } catch (e) { console.error(e); } }); cleanups = []; };

  /* ---------- Toast ---------- */
  function toast(msg, opt) {
    const o = opt || {};
    const type = o.type || 'info', dur = o.dur || 3600;
    const icons = { success: 'check', error: 'alert', warning: 'alert', info: 'bell' };
    const root = $('#toast-root');
    const el = document.createElement('div');
    el.className = 'toast ' + type;
    el.setAttribute('role', 'status');
    el.innerHTML = `<div class="toast-ic">${ic(icons[type])}</div><div class="toast-c">${o.title ? `<b>${o.title}</b>` : ''}<p>${msg}</p></div><button class="toast-x" aria-label="关闭">${ic('x')}</button><i class="toast-bar" style="animation-duration:${dur}ms"></i>`;
    root.appendChild(el);
    let t;
    const close = () => { if (el.classList.contains('out')) return; clearTimeout(t); el.classList.add('out'); setTimeout(() => el.remove(), 300); };
    const arm = ms => { clearTimeout(t); t = setTimeout(close, ms); };
    arm(dur);
    el.addEventListener('mouseenter', () => clearTimeout(t));
    el.addEventListener('mouseleave', () => arm(1600));
    el.querySelector('.toast-x').onclick = close;
    while (root.children.length > 4) root.firstElementChild.remove();
    return close;
  }

  /* ---------- 抽屉 / 弹窗 ---------- */
  let layers = [];
  function openLayer(kind, html, opt) {
    const o = opt || {};
    const ov = document.createElement('div'); ov.className = 'overlay';
    const panel = document.createElement('div'); panel.className = kind;
    panel.setAttribute('role', 'dialog'); panel.setAttribute('aria-modal', 'true');
    panel.innerHTML = html;
    document.body.append(ov, panel);
    void panel.offsetWidth;
    ov.classList.add('show'); panel.classList.add('show');
    let closed = false;
    const close = () => {
      if (closed) return; closed = true;
      ov.classList.remove('show'); panel.classList.remove('show');
      setTimeout(() => { ov.remove(); panel.remove(); }, 420);
      layers = layers.filter(l => l !== close);
      o.onClose && o.onClose();
    };
    ov.addEventListener('click', close);
    $$('[data-close]', panel).forEach(b => b.addEventListener('click', close));
    layers.push(close);
    return { panel, close };
  }
  const closeTopLayer = () => { const l = layers[layers.length - 1]; if (l) { l(); return true; } return false; };
  const closeAllLayers = () => layers.slice().forEach(c => c());

  function confirmDialog(o) {
    return new Promise(res => {
      const { panel, close } = openLayer('modal modal-sm', `
        <div class="md-body"><div class="confirm"><div class="confirm-ic ${o.danger ? 'danger' : ''}">${ic(o.danger ? 'alert' : 'shield-check')}</div>
        <div><h3>${o.title}</h3><p>${o.text}</p></div></div></div>
        <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn ${o.danger ? 'btn-danger' : 'btn-primary'}" data-ok>${o.okText || '确认'}</button></div>`,
      { onClose: () => res(false) });
      const ok = panel.querySelector('[data-ok]');
      ok.addEventListener('click', () => { res(true); close(); });
      setTimeout(() => ok.focus(), 60);
    });
  }

  /* ---------- 分段控件 ---------- */
  const seg = (name, opts, val) => `<div class="seg" data-seg="${name}" role="tablist"><span class="seg-ind"></span>${opts.map(([v, l]) => `<button type="button" role="tab" data-v="${v}" class="${v === val ? 'on' : ''}">${l}</button>`).join('')}</div>`;
  function initSeg(root, name, onChange) {
    const el = root.querySelector(`[data-seg="${name}"]`);
    if (!el) return;
    const ind = el.querySelector('.seg-ind');
    const place = () => { const b = el.querySelector('button.on'); if (b) { ind.style.left = b.offsetLeft + 'px'; ind.style.width = b.offsetWidth + 'px'; } };
    ind.style.transition = 'none'; place(); void ind.offsetWidth; ind.style.transition = '';
    el.addEventListener('click', e => {
      const b = e.target.closest('button');
      if (!b || b.classList.contains('on')) return;
      el.querySelectorAll('button').forEach(x => x.classList.toggle('on', x === b));
      place(); onChange(b.dataset.v);
    });
    const ro = new ResizeObserver(place); ro.observe(el); onCleanup(() => ro.disconnect());
  }

  /* ---------- 卡片 & 分页 ---------- */
  const card = (title, body, o) => {
    o = o || {};
    return `<section class="card ${o.cls || ''}" ${o.id ? `id="${o.id}"` : ''}><header class="card-h"><div><h3>${title}</h3>${o.sub ? `<p>${o.sub}</p>` : ''}</div>${o.extra ? `<div class="card-x">${o.extra}</div>` : ''}</header><div class="card-b">${body}</div></section>`;
  };
  function pagerHtml(p, n, total, per) {
    const range = [];
    for (let i = 1; i <= n; i++) {
      if (i === 1 || i === n || Math.abs(i - p) <= 1) range.push(i);
      else if (range[range.length - 1] !== '…') range.push('…');
    }
    const from = total ? (p - 1) * per + 1 : 0, to = Math.min(total, p * per);
    return `<span>显示 ${from}-${to} 条，共 ${total} 条</span><div class="pg-btns">
      <button class="pg" data-pg="${p - 1}" ${p <= 1 ? 'disabled' : ''} aria-label="上一页">${ic('chevron-left')}</button>
      ${range.map(i => i === '…' ? '<span class="pg-gap">…</span>' : `<button class="pg ${i === p ? 'on' : ''}" data-pg="${i}">${i}</button>`).join('')}
      <button class="pg" data-pg="${p + 1}" ${p >= n ? 'disabled' : ''} aria-label="下一页">${ic('chevron-right')}</button></div>`;
  }

  /* 模拟异步操作：按钮 loading → 回调 */
  function busy(btn, ms, fn) {
    btn.classList.add('loading'); btn.disabled = true;
    setTimeout(() => { btn.classList.remove('loading'); btn.disabled = false; fn && fn(); }, ms);
  }

  /* ---------- 事件总线（SSE 推送 → 页面） ---------- */
  const bus = {};
  const on = (n, fn) => { (bus[n] = bus[n] || new Set()).add(fn); return () => bus[n].delete(fn); };
  const emit = (n, d) => (bus[n] || []).forEach(fn => { try { fn(d); } catch (e) { console.error(e); } });
  /* 页面内订阅：路由切换时自动退订 */
  const listen = (n, fn) => onCleanup(on(n, fn));

  /* ---------- 接口调用 ---------- */
  function apiError(e) {
    if (!e || e.status === 401) return; // 401 由全局处理（回到登录页）
    toast(esc(e.message || String(e)), { type: 'error', title: e.status === 403 ? '无权限' : e.status === 0 ? '网络错误' : '操作失败' });
  }
  /* act：按钮进入 loading → 调用接口 → 成功回调；失败自动提示。返回结果或 undefined */
  async function act(btn, fn, ok) {
    if (btn) { btn.classList.add('loading'); btn.disabled = true; }
    try { const r = await fn(); if (ok) ok(r); return r; } catch (e) { apiError(e); return undefined; } finally { if (btn) { btn.classList.remove('loading'); btn.disabled = false; } }
  }
  const canDo = (m, op) => !!(UI.me && UI.me.perms && UI.me.perms[m] && UI.me.perms[m][op || 'view']);

  window.UI = {
    D, C, ic, $, $$, fmt, esc, pad2, reduceMotion, fmtTime, relTime, hue, avatar, store,
    SEV, ACT, ST, sevBadge, actBadge, stBadge, chIcon, pendingHigh,
    onCleanup, runCleanups, toast, openLayer, closeTopLayer, closeAllLayers, confirmDialog,
    seg, initSeg, card, pagerHtml, busy, countUp: C.countUp, on, emit, listen, act, apiError, canDo,
    pages: {}, params: new URLSearchParams(),
    updateNav() {}, pushNote() {}, openIncident() {}
  };
})();
