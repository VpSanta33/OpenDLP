/* ==========================================================================
   应用外壳：登录、权限（三员分立）、导航、路由、主题与界面偏好、
   通知中心、下载任务中心、屏幕水印、命令面板、启动动画
   ========================================================================== */
(function () {
  'use strict';
  const { D, ic, $, $$, esc, pad2, relTime, fmtTime, toast, store, reduceMotion, pages, act, apiError, confirmDialog, openLayer } = UI;
  const app = $('#app');

  /* ---------- 菜单与权限（权限矩阵由后端下发并在服务端强制校验，前端仅做菜单收敛） ---------- */
  const NAV = [
    { key: 'mon', group: '监控中心', items: ['dashboard', 'incidents', 'ueba'] },
    { key: 'pro', group: '数据防护', items: ['policies', 'rules', 'discovery', 'approvals'] },
    { key: 'ast', group: '资产与合规', items: ['endpoints', 'reports', 'audit'] },
    { key: 'sys', group: '系统管理', items: ['iam', 'ops', 'settings'] }
  ];
  UI.NAV = NAV;
  Object.defineProperty(UI, 'ROLE', { get: () => Object.fromEntries(D.roles.map(r => [r.key, r])) });
  UI.me = null;
  UI.can = k => UI.canDo(k, 'view');
  const groupOf = k => (NAV.find(g => g.items.includes(k)) || { group: '系统' }).group;
  const BADGE = {
    incidents: { n: () => UI.pendingHigh() },
    approvals: { n: () => D.approvals.filter(a => a.status === 'pending' && a.stage === 2).length, cls: 'warn' }
  };
  let current = null;

  /* ---------- 无权限页 ---------- */
  pages.forbidden = {
    title: '无访问权限', icon: 'lock',
    html() {
      const p = pages[UI.denied] || { title: '该页面' };
      return `<div class="forbid">
        <div class="forbid-art">${ic('lock')}<span></span><span></span></div>
        <h1>403 · 无访问权限</h1>
        <p>当前角色「${esc(UI.me.roleName)}」无权访问「${p.title}」。<br>根据三员分立原则，该模块由其他管理员角色负责。</p>
        <div class="forbid-act"><a class="btn" href="#/dashboard">${ic('dashboard')}返回总览</a></div>
        <p class="muted small" style="margin-top:12px">如需访问，请联系超级管理员在「组织与权限」中调整角色权限。</p>
      </div>`;
    }
  };

  /* ---------- 导航 ---------- */
  const folded = new Set(store.get('navFold', []));
  function buildNav() {
    $('#nav').innerHTML = '<span class="nav-ind"></span>' + NAV.map(g => {
      const its = g.items.filter(k => pages[k] && UI.can(k));
      if (!its.length) return '';
      const f = folded.has(g.key);
      return `<div class="nav-sec ${f ? 'fold' : ''}" data-g="${g.key}">
        <button class="nav-group" data-n="${its.length}" aria-expanded="${!f}">${g.group}${ic('chevron-down')}</button>
        <div class="nav-sub"><div>${its.map(k => `<a class="nav-item" data-k="${k}" href="#/${k}" data-title="${pages[k].title}">${ic(pages[k].icon)}<span class="nav-label">${pages[k].title}</span>${BADGE[k] ? `<span class="nav-badge ${BADGE[k].cls || ''}" data-badge="${k}"></span>` : ''}</a>`).join('')}</div></div>
      </div>`;
    }).join('');
  }
  function placeNavInd() {
    const a = $('.nav-item.active'), ind = $('.nav-ind');
    if (!ind) return;
    const hidden = !a || (a.closest('.nav-sec.fold') && !app.classList.contains('collapsed'));
    if (hidden) { ind.style.opacity = 0; return; }
    ind.style.top = (a.offsetTop + 9) + 'px'; ind.style.opacity = 1;
  }
  UI.updateNav = function () {
    $$('.nav-item').forEach(a => a.classList.toggle('active', a.dataset.k === current));
    Object.keys(BADGE).forEach(k => {
      const b = $(`[data-badge="${k}"]`); if (!b) return;
      const n = BADGE[k].n();
      b.textContent = n; b.style.display = n ? '' : 'none';
      b.parentElement.classList.toggle('has-badge', n > 0);
    });
    placeNavInd();
  };
  function bindNav() {
    $('#nav').addEventListener('click', e => {
      const g = e.target.closest('.nav-group'); if (!g) return;
      const sec = g.parentElement, k = sec.dataset.g;
      sec.classList.toggle('fold');
      sec.classList.contains('fold') ? folded.add(k) : folded.delete(k);
      g.setAttribute('aria-expanded', !sec.classList.contains('fold'));
      store.set('navFold', Array.from(folded));
      $('.nav-ind').style.opacity = 0;
      setTimeout(placeNavInd, 340);
    });
    // 折叠模式下的菜单悬浮提示
    const tip = document.createElement('div'); tip.className = 'nav-tip'; document.body.appendChild(tip);
    $('#nav').addEventListener('mouseover', e => {
      const a = e.target.closest('.nav-item');
      if (!a || !app.classList.contains('collapsed') || innerWidth <= 900) { tip.classList.remove('show'); return; }
      const r = a.getBoundingClientRect(), b = a.querySelector('.nav-badge');
      tip.innerHTML = esc(a.dataset.title) + (b && b.style.display !== 'none' ? `<small>${b.textContent} 待处理</small>` : '');
      tip.style.left = (r.right + 10) + 'px'; tip.style.top = (r.top + r.height / 2) + 'px';
      tip.classList.add('show');
    });
    $('#nav').addEventListener('mouseleave', () => tip.classList.remove('show'));
    $('#nav').addEventListener('scroll', () => tip.classList.remove('show'));
  }

  /* ---------- 路由 ---------- */
  function route() {
    if (!UI.me) return;
    const [path, qs] = location.hash.replace(/^#\/?/, '').split('?');
    const name = pages[path] && path !== 'forbidden' ? path : 'dashboard';
    UI.params = new URLSearchParams(qs || '');
    UI.runCleanups();
    UI.closeAllLayers();
    closePops();
    current = name;
    UI.denied = UI.can(name) ? null : name;
    const p = UI.denied ? pages.forbidden : pages[name];
    document.title = `${pages[name].title} · OpenDLP`;
    $('#crumbs').innerHTML = `<span class="c-hide">OpenDLP</span><span class="c-hide">${ic('chevron-right')}</span><span class="c-hide">${groupOf(name)}</span><span class="c-hide">${ic('chevron-right')}</span><b>${pages[name].title}</b>`;
    // 当前页面所在分组自动展开
    const g = NAV.find(x => x.items.includes(name));
    if (g && folded.has(g.key)) { folded.delete(g.key); store.set('navFold', Array.from(folded)); const sec = $(`.nav-sec[data-g="${g.key}"]`); sec && sec.classList.remove('fold'); }
    UI.updateNav();
    const view = $('#view');
    view.innerHTML = p.html();
    view.classList.remove('page-in'); void view.offsetWidth; view.classList.add('page-in');
    window.scrollTo(0, 0);
    try { p.mount && p.mount(view); } catch (e) { console.error(e); toast('页面加载异常：' + esc(e.message), { type: 'error' }); }
    UI.applyPerms(view);
    app.classList.remove('nav-open');
  }
  UI.rerender = route;
  /* 按钮级权限：data-perm="模块:操作"，无权限时禁用（服务端同样强制校验） */
  UI.applyPerms = root => $$('[data-perm]', root).forEach(el => {
    const [m, o] = el.dataset.perm.split(':');
    if (!UI.canDo(m, o)) { el.disabled = true; el.classList.add('no-perm'); el.title = '当前角色无此操作权限'; }
  });

  /* ---------- 主题 & 界面偏好 ---------- */
  const mq = window.matchMedia('(prefers-color-scheme: dark)');
  const resolve = m => m === 'system' ? (mq.matches ? 'dark' : 'light') : m;
  function applyTheme(mode) {
    const t = resolve(mode);
    document.documentElement.dataset.theme = t;
    $('#themeBtn').innerHTML = ic(t === 'dark' ? 'sun' : 'moon');
    $('#themeBtn').title = t === 'dark' ? '切换到浅色模式' : '切换到深色模式';
    store.set('theme', mode);
    renderWatermark();
  }
  mq.addEventListener && mq.addEventListener('change', () => { if (store.get('theme', 'system') === 'system') applyTheme('system'); });
  function withReveal(fn, e) {
    if (!document.startViewTransition || reduceMotion) { fn(); return; }
    const r0 = $('#themeBtn').getBoundingClientRect();
    const x = e && e.clientX ? e.clientX : r0.left + r0.width / 2;
    const y = e && e.clientY ? e.clientY : r0.top + r0.height / 2;
    const r = Math.hypot(Math.max(x, innerWidth - x), Math.max(y, innerHeight - y));
    const vt = document.startViewTransition(fn);
    vt.ready.then(() => {
      document.documentElement.animate(
        { clipPath: [`circle(0px at ${x}px ${y}px)`, `circle(${r}px at ${x}px ${y}px)`] },
        { duration: 560, easing: 'cubic-bezier(.4,0,.2,1)', pseudoElement: '::view-transition-new(root)' });
    }).catch(() => {});
  }
  function toggleTheme(e) {
    const next = document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark';
    withReveal(() => applyTheme(next), e);
  }
  const PREF_DEF = { side: 'theme', accent: 'blue', density: 'comfortable', wm: true };
  const pref = k => store.get(k, PREF_DEF[k]);
  function applyPrefs() {
    const h = document.documentElement;
    pref('side') === 'theme' ? h.removeAttribute('data-side') : h.dataset.side = pref('side');
    pref('accent') === 'blue' ? h.removeAttribute('data-accent') : h.dataset.accent = pref('accent');
    pref('density') === 'compact' ? h.dataset.density = 'compact' : h.removeAttribute('data-density');
    renderWatermark();
  }
  UI.applyPrefs = applyPrefs;

  function renderWatermark() {
    let el = $('#wm');
    if (!el) { el = document.createElement('div'); el.id = 'wm'; el.setAttribute('aria-hidden', 'true'); document.body.appendChild(el); }
    const on = pref('wm') && UI.me;
    el.classList.toggle('off', !on);
    if (!on) return;
    const dark = document.documentElement.dataset.theme === 'dark', d = new Date();
    const fill = dark ? 'rgba(255,255,255,.04)' : 'rgba(15,27,45,.05)';
    const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="340" height="210"><g transform="rotate(-22 170 105)" fill="${fill}" font-family="-apple-system,PingFang SC,Microsoft YaHei,sans-serif" font-size="13"><text x="56" y="100">${esc(UI.me.name)} ${esc(UI.me.acc)}</text><text x="56" y="120">${esc(UI.me.ip || '')} · ${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}</text></g></svg>`;
    el.style.backgroundImage = `url("data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}")`;
  }

  const ACCENTS = [['blue', '科技蓝', '#2563eb'], ['indigo', '靛青', '#4f46e5'], ['teal', '松石绿', '#0d9488'], ['violet', '典雅紫', '#7c3aed'], ['crimson', '中国红', '#c0262d']];
  function openAppearance() {
    const th = store.get('theme', 'system');
    const prev = (pb, ps, pi, pc) => `<span class="ap-prev" style="--pb:${pb};--ps:${ps};--pi:${pi};--pc:${pc || ps}"><i></i><em><b></b><b></b><b></b></em></span>`;
    const opt = (grp, v, cur, label, preview) => `<button class="ap-opt ${v === cur ? 'on' : ''}" data-grp="${grp}" data-v="${v}">${preview}<span>${ic('check')}${label}</span></button>`;
    const html = `
      <div class="dr-head"><div class="dr-meta"><span class="tag b-primary">${ic('palette')}界面偏好</span></div>
        <h2>外观与显示</h2><p>设置仅保存在当前浏览器</p>
        <button class="icon-btn dr-close" data-close aria-label="关闭">${ic('x')}</button></div>
      <div class="dr-body ap">
        <h4 class="sec-t">主题模式</h4>
        <div class="ap-grid">
          ${opt('theme', 'light', th, '浅色', prev('#f3f5f9', '#ffffff', '#e4e9f0'))}
          ${opt('theme', 'dark', th, '深色', prev('#0a1120', '#0f1a2c', '#1d2c44'))}
          ${opt('theme', 'system', th, '跟随系统', '<span class="ap-prev split"><span>' + prev('#f3f5f9', '#ffffff', '#e4e9f0') + '</span><span>' + prev('#0a1120', '#0f1a2c', '#1d2c44') + '</span></span>')}
        </div>
        <h4 class="sec-t">导航栏风格</h4>
        <div class="ap-grid">
          ${opt('side', 'theme', pref('side'), '与页面统一', prev('var(--bg)', 'var(--surface)', 'var(--primary-weak)', 'var(--surface)'))}
          ${opt('side', 'dark', pref('side'), '深色导航', prev('var(--bg)', '#0b1424', 'rgba(var(--primary-rgb),.5)', 'var(--surface)'))}
          ${opt('side', 'brand', pref('side'), '品牌色导航', prev('var(--bg)', 'color-mix(in srgb, var(--primary) 78%, #050b18)', 'rgba(255,255,255,.35)', 'var(--surface)'))}
        </div>
        <h4 class="sec-t">主题色 <small>用于按钮、选中态与图表主色</small></h4>
        <div class="ap-sw">${ACCENTS.map(([k, n, c]) => `<button class="sw ${pref('accent') === k ? 'on' : ''}" data-grp="accent" data-v="${k}" style="--sw:${c}" title="${n}"><i>${ic('check')}</i><span>${n}</span></button>`).join('')}</div>
        <h4 class="sec-t">界面密度</h4>
        ${UI.seg('density', [['comfortable', '舒适'], ['compact', '紧凑']], pref('density'))}
        <h4 class="sec-t">安全</h4>
        <label class="set-row"><div><b>屏幕安全水印</b><small>在控制台叠加当前账号与 IP，便于追溯截屏、拍照外传</small></div><span class="switch"><input type="checkbox" id="apWm" ${pref('wm') ? 'checked' : ''}><span></span></span></label>
      </div>
      <div class="dr-foot"><button class="btn" id="apReset">${ic('refresh')}恢复默认</button><span class="sp"></span><button class="btn btn-primary" data-close>${ic('check')}完成</button></div>`;
    const { panel } = openLayer('drawer drawer-sm', html);
    const mark = (grp, v) => $$(`[data-grp="${grp}"]`, panel).forEach(b => b.classList.toggle('on', b.dataset.v === v));
    panel.addEventListener('click', e => {
      const b = e.target.closest('[data-grp]'); if (!b) return;
      const grp = b.dataset.grp, v = b.dataset.v;
      if (grp === 'theme') withReveal(() => applyTheme(v), e);
      else { store.set(grp, v); applyPrefs(); setTimeout(placeNavInd, 50); }
      mark(grp, v);
    });
    UI.initSeg(panel, 'density', v => { store.set('density', v); applyPrefs(); setTimeout(() => { placeNavInd(); window.dispatchEvent(new Event('resize')); }, 60); });
    panel.querySelector('#apWm').addEventListener('change', e => { store.set('wm', e.target.checked); applyPrefs(); });
    panel.querySelector('#apReset').addEventListener('click', () => {
      Object.entries(PREF_DEF).forEach(([k, v]) => store.set(k, v));
      applyTheme('system'); applyPrefs();
      ['side', 'accent'].forEach(g => mark(g, PREF_DEF[g])); mark('theme', 'system');
      panel.querySelector('#apWm').checked = true;
      toast('界面偏好已恢复默认', { type: 'info' });
    });
  }
  UI.openAppearance = openAppearance;

  /* ---------- 下载 / 任务中心（后端异步任务：导出、报表、规则库更新） ---------- */
  let tasks = [];
  const polling = new Set();
  function renderTasks() {
    const run = tasks.filter(t => t.status === 'run').length;
    const b = $('#taskBtn .cnt-badge'); b.textContent = run; b.style.display = run ? '' : 'none';
    $('#taskBtn').classList.toggle('running', run > 0);
    $('#taskPop').innerHTML = `<div class="pop-h"><b>下载中心</b><span class="muted">${run ? run + ' 个任务进行中' : '全部任务已完成'}</span><button class="link" id="clrTask">清除已完成</button></div>
      <ul class="tasks">${tasks.length ? tasks.slice(0, 10).map(t => `<li class="task ${t.status}" data-id="${t.id}">
        <span class="task-ic">${ic(t.status === 'run' ? 'refresh' : t.status === 'failed' ? 'alert' : 'file-text')}</span>
        <div class="task-m"><b title="${esc(t.name)}">${esc(t.name)}</b>
          ${t.status === 'run' ? `<div class="progress"><i style="width:${t.progress}%"></i></div><small>正在生成… ${t.progress}%</small>`
            : t.status === 'failed' ? `<small class="danger-t">失败：${esc(t.error || '')}</small>` : `<small>${t.size || '已完成'} · ${relTime(t.done || t.created)}</small>`}</div>
        ${t.download ? `<button class="icon-btn sm" data-dl="${t.id}" aria-label="下载">${ic('download')}</button>` : ''}</li>`).join('') : `<li class="cmdk-empty">${ic('inbox')}<p>暂无下载任务</p></li>`}</ul>
      <div class="pop-f muted small">生成的文件保存在服务端内存中 7 天（重启后清空）· 下载记入审计日志</div>`;
  }
  function upsertTask(j) {
    const i = tasks.findIndex(t => t.id === j.id);
    i >= 0 ? tasks[i] = j : tasks.unshift(j);
    renderTasks();
  }
  function poll(id, resolve) {
    if (polling.has(id)) return;
    polling.add(id);
    const tick = async () => {
      if (!UI.me) { polling.delete(id); return; }
      try {
        const j = await API.get('/jobs/' + id);
        upsertTask(j);
        if (j.status === 'run') { setTimeout(tick, 500); return; }
        polling.delete(id);
        if (j.status === 'done') {
          if (j.download) toast(`${esc(j.name)} 已生成，可在右上角下载中心获取`, { type: 'success', title: '任务完成' });
        } else toast(esc(j.error || '任务失败'), { type: 'error', title: esc(j.name) });
        resolve && resolve(j);
      } catch (e) { polling.delete(id); }
    };
    setTimeout(tick, 400);
  }
  /* UI.task(start)：start 返回后端 Job（POST 接口的响应）；返回任务结束时的 Job */
  UI.task = async function (start) {
    let j;
    try { j = await start(); } catch (e) { apiError(e); return null; }
    if (!j || !j.id) return null;
    upsertTask(j);
    const b = $('#taskBtn'); b.classList.remove('bump'); void b.offsetWidth; b.classList.add('bump');
    toast(`「${esc(j.name)}」已加入下载中心，完成后将通知您`, { type: 'info', title: '任务已创建', dur: 2400 });
    return new Promise(res => poll(j.id, res));
  };
  async function loadTasks() {
    try { tasks = await API.get('/jobs'); renderTasks(); tasks.filter(t => t.status === 'run').forEach(t => poll(t.id)); } catch (e) { /* 忽略 */ }
  }

  /* ---------- 通知 & 用户菜单 ---------- */
  const NOTE_IC = { danger: 'alert', warning: 'alert', success: 'check', info: 'bell' };
  function renderNotes(freshFirst) {
    const unread = D.notes.filter(n => n.unread).length;
    $('#bellBtn .dot').style.display = unread ? '' : 'none';
    $('#notePop').innerHTML = `<div class="pop-h"><b>通知中心</b><span class="muted">${unread} 条未读</span><button class="link" id="readAll">全部已读</button></div>
      <ul class="notes">${D.notes.slice(0, 8).map((n, i) => `<li class="note ${n.unread ? 'unread' : ''} ${freshFirst && i === 0 ? 'fresh' : ''}" data-i="${i}"><span class="note-ic n-${n.type}">${ic(NOTE_IC[n.type])}</span><div><b>${n.title}</b><p>${esc(n.text)}</p><time>${relTime(n.ts)}</time></div></li>`).join('')}</ul>
      <a class="pop-f" href="#/audit">查看全部通知记录</a>`;
  }
  UI.pushNote = n => {
    D.notes.unshift(n); if (D.notes.length > 30) D.notes.pop();
    renderNotes(true);
    const b = $('#bellBtn'); b.classList.remove('ring'); void b.offsetWidth; b.classList.add('ring');
  };
  function renderUser() {
    const me = UI.me, r = UI.ROLE[me.role] || { color: 'primary' };
    $('#userBtn .avatar').textContent = me.name[0];
    $('#userBtn .user-txt').innerHTML = `<b>${esc(me.name)}</b><small>${esc(me.acc)} · ${esc(me.roleName)}</small>`;
    $('#userPop').innerHTML = `<div class="pm-head"><span class="avatar lg">${esc(me.name[0])}</span><div><b>${esc(me.name)}</b><small>${esc(me.acc)}@corp.example</small><span class="tag b-${r.color}">${esc(me.roleName)}</span>${me.mfa ? '' : '<span class="tag b-warning">未启用 MFA</span>'}</div></div>
      ${me.canSwitch ? `<div class="pm-sec">切换身份 <small>开发模式 · 演示三员分立</small></div>
      ${['super', 'sysadmin', 'secadmin', 'auditor'].map(k => `<button class="pm-item ${me.role === k ? 'cur' : ''}" data-role="${k}">${ic(me.role === k ? 'check' : 'user')}${esc((UI.ROLE[k] || {}).name || k)}</button>`).join('')}
      <div class="pm-div"></div>` : ''}
      <button class="pm-item" data-u="pwd">${ic('key')}修改口令</button>
      <button class="pm-item" data-u="appear">${ic('palette')}界面偏好</button>
      <div class="pm-div"></div>
      <button class="pm-item danger" data-u="logout">${ic('logout')}退出登录</button>`;
  }
  const pops = () => [$('#notePop'), $('#userPop'), $('#taskPop')];
  function closePops() { pops().forEach(p => p.classList.remove('show')); }
  function togglePop(p) { const open = p.classList.contains('show'); closePops(); if (!open) p.classList.add('show'); }

  async function switchRole(role) {
    try {
      await API.post('/auth/role', { role });
      await enter();
      toast(`已切换为「${esc(UI.me.roleName)}」视角，菜单、数据与操作权限均由服务端按角色收敛`, { type: 'info', title: '身份已切换' });
    } catch (e) { apiError(e); }
  }

  /* ---------- 命令面板 ---------- */
  let cmdk = null, sel = 0, items = [];
  const cmdItems = () => [
    ...Object.keys(pages).filter(k => k !== 'forbidden' && UI.can(k)).map(k => ({ sec: '页面', label: pages[k].title, icon: pages[k].icon, hint: groupOf(k), run: () => { location.hash = '#/' + k; } })),
    ...[
      ['policies', '新建防泄漏策略', 'plus', 'policy new', '#/policies?new=1'],
      ['incidents', '查看待处置的严重事件', 'zap', 'critical', '#/incidents?sev=critical&st=pending'],
      ['approvals', '处理待我审批的外发申请', 'stamp', 'approve', '#/approvals'],
      ['rules', '测试敏感数据识别规则', 'wand', 'regex test rule', '#/rules?test=1'],
      ['discovery', '启动敏感数据扫描', 'play', 'scan', '#/discovery?scan=1'],
      ['reports', '生成合规报告', 'file-text', 'report pipl', '#/reports']
    ].filter(x => UI.can(x[0])).map(([, label, icon, kw, href]) => ({ sec: '快捷操作', label, icon, kw, run: () => { location.hash = href; } })),
    { sec: '快捷操作', label: '切换深色 / 浅色主题', icon: 'moon', kw: 'theme dark light', run: () => toggleTheme() },
    { sec: '快捷操作', label: '界面偏好设置', icon: 'palette', kw: 'appearance color', run: () => openAppearance() }
  ];
  function openCmdk() {
    if (cmdk || !UI.me) return;
    closePops();
    cmdk = document.createElement('div');
    cmdk.className = 'cmdk-ov';
    cmdk.innerHTML = `<div class="cmdk" role="dialog" aria-label="命令面板"><div class="cmdk-in">${ic('search')}<input id="cmdkQ" placeholder="搜索页面、事件 ID、用户或操作…" autocomplete="off"><kbd>ESC</kbd></div>
      <div class="cmdk-list" id="cmdkList"></div>
      <div class="cmdk-foot"><span><kbd>↑</kbd><kbd>↓</kbd> 选择</span><span><kbd>↵</kbd> 执行</span><span><kbd>esc</kbd> 关闭</span></div></div>`;
    document.body.appendChild(cmdk);
    void cmdk.offsetWidth; cmdk.classList.add('show');
    const qi = $('#cmdkQ');
    sel = 0; renderCmdk('');
    qi.focus();
    qi.addEventListener('input', () => { sel = 0; renderCmdk(qi.value.trim()); });
    qi.addEventListener('keydown', e => {
      if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
      else if (e.key === 'Enter') { e.preventDefault(); runSel(); }
    });
    cmdk.addEventListener('mousedown', e => { if (e.target === cmdk) closeCmdk(); });
  }
  function closeCmdk() {
    if (!cmdk) return;
    const el = cmdk; cmdk = null;
    el.classList.remove('show'); setTimeout(() => el.remove(), 220);
  }
  function renderCmdk(q) {
    const ql = q.toLowerCase();
    items = cmdItems().filter(it => !q || (it.label + (it.kw || '') + (it.hint || '')).toLowerCase().includes(ql));
    if (q.length >= 2 && UI.can('incidents')) {
      items = items.concat(D.incidents.filter(i => (i.id + i.user + i.file).toLowerCase().includes(ql)).slice(0, 6).map(i => ({
        sec: '事件', label: `${i.id} · ${i.user} · ${i.file}`, icon: 'alert', hint: UI.SEV[i.severity].name,
        run: () => { if (current !== 'incidents') location.hash = '#/incidents'; setTimeout(() => UI.openIncident(i.id), 80); }
      })));
    }
    if (q.length >= 1 && UI.can('ueba')) {
      items = items.concat((D.employees || []).filter(u => u.name.includes(q)).slice(0, 4).map(u => ({
        sec: '用户', label: `${u.name} · ${u.dept}`, icon: 'user', hint: '风险画像', run: () => { location.hash = '#/ueba?u=' + u.id; }
      })));
    }
    const box = $('#cmdkList');
    if (!items.length) { box.innerHTML = `<div class="cmdk-empty">${ic('search')}<p>未找到「${esc(q)}」相关结果</p></div>`; return; }
    let html = '', sec = '';
    items.forEach((it, i) => {
      if (it.sec !== sec) { sec = it.sec; html += `<div class="cmdk-sec">${sec}</div>`; }
      html += `<div class="cmdk-item ${i === sel ? 'on' : ''}" data-i="${i}">${ic(it.icon)}<span>${esc(it.label)}</span><small>${it.hint || ''}</small></div>`;
    });
    box.innerHTML = html;
    $$('.cmdk-item', box).forEach(el => {
      el.addEventListener('mousemove', () => { if (sel !== +el.dataset.i) { sel = +el.dataset.i; mark(); } });
      el.addEventListener('click', () => { sel = +el.dataset.i; runSel(); });
    });
  }
  function mark() { $$('.cmdk-item').forEach(el => el.classList.toggle('on', +el.dataset.i === sel)); const on = $('.cmdk-item.on'); on && on.scrollIntoView({ block: 'nearest' }); }
  function move(d) { if (!items.length) return; sel = (sel + d + items.length) % items.length; mark(); }
  function runSel() { const it = items[sel]; if (!it) return; closeCmdk(); it.run(); }

  /* ---------- 登录 ---------- */
  let authCfg = { dev: false };
  function showLogin(reason) {
    if ($('#login')) return;
    UI.me = null;
    const last = store.get('lastAcc', 'admin');
    const el = document.createElement('div');
    el.id = 'login'; el.className = 'login';
    el.innerHTML = `
      <section class="lg-art">
        <div class="lg-grid"></div>
        <div class="lg-orbit"><span></span><span></span><span></span>
          <div class="lg-shield">${ic('shield-check')}</div>
          <i class="o1">${ic('mail')}</i><i class="o2">${ic('usb')}</i><i class="o3">${ic('cloud')}</i><i class="o4">${ic('message')}</i><i class="o5">${ic('printer')}</i><i class="o6">${ic('globe')}</i>
        </div>
        <div class="lg-copy">
          <div class="lg-brand"><span class="brand-logo">${ic('shield-check')}</span>OpenDLP</div>
          <h1>数据防泄漏<br>管理控制台</h1>
          <p>终端 Agent 检测 U 盘与同步目录中的敏感文件，网关等系统可通过接口上报；在这里统一配置策略、处置事件、审批外发并留存审计记录。</p>
          <ul><li>${ic('check')}内容识别与策略处置</li><li>${ic('check')}事件告警与用户风险评分</li><li>${ic('check')}三员分立权限与审计追溯</li></ul>
          <div class="lg-cert"><span>TOTP 双因素认证</span><span>审计日志哈希链</span><span>三员分立权限模型</span></div>
        </div>
      </section>
      <section class="lg-panel"><div class="lg-box">
        <div class="lg-head"><h2>登录管理控制台</h2><p>${reason ? esc(reason) : '欢迎使用 OpenDLP 企业数据防泄漏平台'}</p></div>
        <div class="lg-pane on" data-p="pwd">
          <form id="lgForm" novalidate>
            <div class="field"><label class="lbl" for="lgAcc">管理员账号</label><div class="in-ic">${ic('user')}<input class="input" id="lgAcc" value="${esc(last)}" autocomplete="username"></div></div>
            <div class="field"><label class="lbl" for="lgPwd">口令</label><div class="in-ic">${ic('lock')}<input class="input" id="lgPwd" type="password" placeholder="请输入口令" autocomplete="current-password"><button type="button" class="in-eye" id="lgEye" aria-label="显示口令">${ic('eye')}</button></div>
              <div class="field-err" id="lgErr"></div></div>
            <div class="lg-row"><label class="ck-l"><input type="checkbox" id="lgRem" checked>记住账号</label><button type="button" class="link" id="lgForgot">忘记口令？</button></div>
            <button class="btn btn-primary btn-lg" type="submit" id="lgSubmit">登 录</button>
          </form>
          <div class="lg-demo" id="lgDemo" hidden><span>演示环境账号（口令见 README；开发模式下动态码打印在服务端日志中）：</span>${[['admin', '超级管理员'], ['sec_lihua', '安全管理员'], ['sys_zhou', '系统管理员'], ['audit_zhao', '审计管理员']].map(([a, n]) => `<button type="button" data-acc="${a}" title="${a}">${n}</button>`).join('')}</div>
        </div>
        <div class="lg-pane" data-p="otp">
          <button class="link back" id="otpBack">${ic('chevron-left')}返回</button>
          <div class="otp-ic">${ic('phone')}</div>
          <h3>双因素身份验证</h3>
          <p class="muted small">请输入身份验证器（如 Google Authenticator、Microsoft Authenticator）中的 6 位动态码<br><span id="otpWho"></span></p>
          <div class="otp" id="otp">${'<input inputmode="numeric" autocomplete="one-time-code" aria-label="验证码">'.repeat(6)}</div>
          <div class="field-err" id="otpErr" style="text-align:center"></div>
          <p class="muted small otp-hint" id="otpHint" hidden>开发模式：动态码已打印在服务端日志中</p>
        </div>
        <div class="lg-foot">${ic('lock')}${location.protocol === 'https:' ? '已通过 HTTPS 加密传输' : '当前未使用 HTTPS，请勿在公网环境使用'} · 登录行为将记录至审计日志</div>
      </div>
      <div class="lg-copy-r" id="lgVer">OpenDLP</div></section>`;
    document.body.appendChild(el);
    app.classList.add('locked');
    requestAnimationFrame(() => el.classList.add('show'));

    const q = s => el.querySelector(s);
    let challenge = null;
    API.get('/auth/config').then(c => {
      authCfg = c;
      q('#lgDemo').hidden = !c.demo; q('#otpHint').hidden = !c.dev;
      if (c.version) q('#lgVer').textContent = 'OpenDLP · v' + c.version;
    }).catch(() => {});
    const showPane = p => { $$('.lg-pane', el).forEach(x => x.classList.toggle('on', x.dataset.p === p)); };

    const shake = () => { const box = q('.lg-box'); box.classList.remove('shake'); void box.offsetWidth; box.classList.add('shake'); };
    const err = (m, input, id) => {
      const e = q(id || '#lgErr'); e.textContent = m; e.classList.add('show');
      shake(); input && input.classList.add('err');
    };
    $$('#lgAcc, #lgPwd', el).forEach(i => i.addEventListener('input', () => { i.classList.remove('err'); q('#lgErr').classList.remove('show'); }));
    q('#lgEye').addEventListener('click', () => { const p = q('#lgPwd'); p.type = p.type === 'password' ? 'text' : 'password'; q('#lgEye').innerHTML = ic(p.type === 'password' ? 'eye' : 'lock'); });
    q('#lgDemo').addEventListener('click', e => { const b = e.target.closest('[data-acc]'); if (!b) return; q('#lgAcc').value = b.dataset.acc; q('#lgAcc').classList.remove('err'); q('#lgErr').classList.remove('show'); q('#lgPwd').focus(); });
    q('#lgForgot').addEventListener('click', () => toast('请联系系统管理员在「组织与权限 → 管理员账号」中重置口令', { type: 'info', title: '忘记口令' }));
    q('#lgForm').addEventListener('submit', async e => {
      e.preventDefault();
      const acc = q('#lgAcc').value.trim(), pwd = q('#lgPwd').value;
      if (!acc) return err('请输入管理员账号', q('#lgAcc'));
      if (!pwd) return err('请输入口令', q('#lgPwd'));
      const btn = q('#lgSubmit'); btn.classList.add('loading'); btn.disabled = true;
      try {
        const r = await API.post('/auth/login', { account: acc, password: pwd }, { quiet401: true });
        store.set('lastAcc', q('#lgRem').checked ? acc : '');
        q('#lgPwd').value = '';
        if (!r.mfa) return finish(r, r.warn);
        challenge = r.challenge;
        q('#otpWho').textContent = `账号：${r.account}（${r.name}）`;
        showPane('otp');
        setTimeout(() => q('#otp input').focus(), 260);
      } catch (ex) { err(ex.message, ex.status === 401 ? q('#lgPwd') : null); }
      finally { btn.classList.remove('loading'); btn.disabled = false; }
    });
    const otps = $$('#otp input', el);
    const resetOtp = () => { q('#otp').classList.remove('verifying', 'ok'); otps.forEach(i => { i.disabled = false; i.value = ''; }); otps[0].focus(); };
    const backToPwd = () => { showPane('pwd'); otps.forEach(i => { i.value = ''; }); challenge = null; };
    q('#otpBack').addEventListener('click', backToPwd);
    const otpCheck = async () => {
      const v = otps.map(i => i.value).join('');
      if (v.length < 6) return;
      otps.forEach(i => { i.disabled = true; });
      q('#otp').classList.add('verifying');
      try {
        const r = await API.post('/auth/mfa', { challenge, code: v }, { quiet401: true });
        q('#otp').classList.add('ok');
        setTimeout(() => finish(r), 420);
      } catch (ex) {
        resetOtp();
        err(ex.message, null, '#otpErr');
        if (/过期/.test(ex.message)) setTimeout(backToPwd, 1200);
      }
    };
    otps.forEach((inp, i) => {
      inp.addEventListener('input', () => {
        // 快速输入或输入法一次带入多位时，依次溢出到后续格子
        const ds = inp.value.replace(/\D/g, '');
        q('#otpErr').classList.remove('show');
        if (!ds) { inp.value = ''; return; }
        ds.split('').forEach((c, k) => { if (otps[i + k]) otps[i + k].value = c; });
        const next = otps.find((x, k) => k > i && !x.value) || otps[Math.min(5, i + ds.length)];
        next.focus();
        otpCheck();
      });
      inp.addEventListener('keydown', e => { if (e.key === 'Backspace' && !inp.value && otps[i - 1]) { otps[i - 1].focus(); otps[i - 1].value = ''; } });
      inp.addEventListener('paste', e => {
        e.preventDefault();
        const t = (e.clipboardData.getData('text') || '').replace(/\D/g, '').slice(0, 6);
        t.split('').forEach((c, k) => { if (otps[k]) otps[k].value = c; });
        (otps[t.length] || otps[5]).focus(); otpCheck();
      });
    });
    async function finish(r, warn, via) {
      let entered;
      try { entered = await enter(); } catch (ex) { err(ex.message); return; }
      el.classList.add('out');
      setTimeout(() => el.remove(), 700);
      if (!entered) return;
      setTimeout(() => {
        toast(`欢迎回来，${esc(r.name)}。${r.last ? `上次登录 ${fmtTime(r.last).slice(0, 11)}，来自 ${esc(r.lastIp || '-')}` : ''}${via ? ' · 本次通过' + via + '登录' : ''}`, { type: 'success', title: '登录成功', dur: 4200 });
        if (warn) toast(esc(warn), { type: 'warning', title: '安全提示' });
      }, 500);
    }
  }

  /* ---------- 修改口令 ---------- */
  const pwdFields = (cur) => `
    <div class="field"><label class="lbl" for="pcOld">${cur}</label><div class="in-ic">${ic('lock')}<input class="input" id="pcOld" type="password" autocomplete="current-password"></div></div>
    <div class="field"><label class="lbl" for="pcNew">新口令 <span class="hint">≥ 12 位，含大小写字母、数字与符号，不含账号名</span></label><div class="in-ic">${ic('key')}<input class="input" id="pcNew" type="password" autocomplete="new-password"></div></div>
    <div class="field"><label class="lbl" for="pcNew2">确认新口令</label><div class="in-ic">${ic('key')}<input class="input" id="pcNew2" type="password" autocomplete="new-password"></div><div class="field-err" id="pcErr"></div></div>`;
  // 校验并提交，成功返回 true
  async function submitPwd(root, btn, onErr) {
    const g = s => root.querySelector(s);
    const body = { old: g('#pcOld').value, new: g('#pcNew').value };
    if (!body.old || !body.new) return onErr('请填写全部字段'), false;
    if (body.new !== g('#pcNew2').value) return onErr('两次输入的新口令不一致'), false;
    if (body.new === body.old) return onErr('新口令不能与当前口令相同'), false;
    const r = await act(btn, () => API.post('/auth/password', body).catch(ex => { onErr(ex.message); return null; }));
    return !!r;
  }
  // 强制改密（首次登录 / 管理员重置 / 口令过期）：全屏界面，完成前无法使用控制台
  function showPwdChange(me) {
    if ($('#pwdc')) return;
    const el = document.createElement('div');
    el.id = 'pwdc'; el.className = 'login';
    el.innerHTML = `
      <section class="lg-art"><div class="lg-grid"></div>
        <div class="lg-copy"><div class="lg-brand"><span class="brand-logo">${ic('shield-check')}</span>OpenDLP</div>
          <h1>请设置新口令</h1>
          <p>${esc(me.pwdChange)}。修改完成后，该账号在其他设备上的会话将全部下线。</p>
          <ul><li>${ic('check')}口令仅以 PBKDF2 哈希保存</li><li>${ic('check')}修改操作写入审计日志</li></ul></div></section>
      <section class="lg-panel"><div class="lg-box">
        <div class="lg-head"><h2>修改口令</h2><p>${esc(me.name)}（${esc(me.acc)}）</p></div>
        <div class="lg-pane on"><form id="pcForm" novalidate>${pwdFields('当前口令（初始口令或原口令）')}
          <button class="btn btn-primary btn-lg" type="submit" id="pcOk">确认修改并进入控制台</button>
          <button class="btn btn-ghost" type="button" id="pcOut" style="width:100%;margin-top:8px">退出登录</button></form></div>
        <div class="lg-foot">${ic('lock')}修改前无法访问控制台的任何功能</div>
      </div></section>`;
    document.body.appendChild(el);
    app.classList.add('locked');
    requestAnimationFrame(() => el.classList.add('show'));
    const q = x => el.querySelector(x);
    const err = m => { const e = q('#pcErr'); e.textContent = m; e.classList.add('show'); const b = q('.lg-box'); b.classList.remove('shake'); void b.offsetWidth; b.classList.add('shake'); };
    setTimeout(() => q('#pcOld').focus(), 300);
    q('#pcForm').addEventListener('submit', async e => {
      e.preventDefault();
      if (!await submitPwd(el, q('#pcOk'), err)) return;
      try { await enter(); } catch (ex) { err(ex.message); return; }
      el.classList.add('out'); setTimeout(() => el.remove(), 700);
      toast('口令已修改，其他设备上的会话已下线', { type: 'success', title: '修改成功' });
    });
    q('#pcOut').addEventListener('click', async () => {
      try { await API.post('/auth/logout'); } catch (e) { /* 忽略 */ }
      el.remove(); showLogin('您已退出登录');
    });
  }
  // 主动修改口令（用户菜单）
  function openPwdChange() {
    const { panel, close } = openLayer('modal', `
      <div class="md-head"><div><h2>修改口令</h2><p>修改后其他设备上的会话将全部下线</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
      <div class="md-body">${pwdFields('当前口令')}</div>
      <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('save')}确认修改</button></div>`);
    const err = m => { const e = panel.querySelector('#pcErr'); e.textContent = m; e.classList.add('show'); };
    panel.querySelector('[data-ok]').addEventListener('click', async e => {
      if (!await submitPwd(panel, e.currentTarget, err)) return;
      close(); toast('口令已修改，其他设备上的会话已下线', { type: 'success', title: '修改成功' });
    });
  }

  /* ---------- 首次初始化：创建超级管理员并绑定 MFA ---------- */
  function showSetup() {
    if ($('#login')) return;
    const el = document.createElement('div');
    el.id = 'login'; el.className = 'login';
    el.innerHTML = `
      <section class="lg-art"><div class="lg-grid"></div>
        <div class="lg-copy"><div class="lg-brand"><span class="brand-logo">${ic('shield-check')}</span>OpenDLP</div>
          <h1>欢迎使用<br>OpenDLP 数据防泄漏平台</h1>
          <p>首次使用需要创建超级管理员。完成后可在「组织与权限」中按三员分立原则创建系统管理员、安全管理员与审计管理员，并建议日常停用超级管理员。</p>
          <ul><li>${ic('check')}初始化令牌仅打印在服务启动日志中</li><li>${ic('check')}超级管理员强制绑定双因素认证</li><li>${ic('check')}初始化操作写入审计日志</li></ul></div></section>
      <section class="lg-panel"><div class="lg-box">
        <div class="lg-head"><h2>系统初始化</h2><p id="suSub">第 1 步 / 共 2 步 · 创建超级管理员</p></div>
        <div class="lg-pane on" data-p="s1"><form id="suForm" novalidate>
          <div class="field"><label class="lbl" for="suTok">初始化令牌 <span class="hint">见服务启动日志</span></label><div class="in-ic">${ic('key')}<input class="input mono" id="suTok" autocomplete="off"></div></div>
          <div class="field"><label class="lbl" for="suAcc">管理员账号</label><div class="in-ic">${ic('user')}<input class="input" id="suAcc" placeholder="小写字母开头，3-24 位" autocomplete="username"></div></div>
          <div class="field"><label class="lbl" for="suName">姓名</label><div class="in-ic">${ic('users')}<input class="input" id="suName"></div></div>
          <div class="field"><label class="lbl" for="suPwd">口令 <span class="hint">≥ 12 位，含大小写字母、数字与符号</span></label><div class="in-ic">${ic('lock')}<input class="input" id="suPwd" type="password" autocomplete="new-password"></div></div>
          <div class="field"><label class="lbl" for="suPwd2">确认口令</label><div class="in-ic">${ic('lock')}<input class="input" id="suPwd2" type="password" autocomplete="new-password"></div><div class="field-err" id="suErr"></div></div>
          <button class="btn btn-primary btn-lg" type="submit" id="suNext">下一步：绑定双因素认证</button></form></div>
        <div class="lg-pane" data-p="s2">
          <p class="muted small">在身份验证器 App（Google Authenticator、Microsoft Authenticator 等）中手动添加以下密钥，或导入 otpauth 地址：</p>
          <div class="field" style="margin-top:12px"><label class="lbl">密钥</label><div class="secret-box" id="suSecret"></div></div>
          <div class="field"><label class="lbl">otpauth 地址</label><div class="secret-box small" id="suUri"></div></div>
          <label class="lbl" style="justify-content:center;margin-top:14px">输入验证器中显示的 6 位动态码</label>
          <div class="otp" id="suOtp">${'<input inputmode="numeric" autocomplete="one-time-code" aria-label="动态码">'.repeat(6)}</div>
          <div class="field-err" id="suErr2" style="text-align:center"></div>
        </div>
        <div class="lg-foot">${ic('lock')}初始化完成后令牌立即失效</div>
      </div></section>`;
    document.body.appendChild(el);
    app.classList.add('locked');
    requestAnimationFrame(() => el.classList.add('show'));
    const q = x => el.querySelector(x);
    const err = (m, id) => { const e = q(id || '#suErr'); e.textContent = m; e.classList.add('show'); const b = q('.lg-box'); b.classList.remove('shake'); void b.offsetWidth; b.classList.add('shake'); };
    let enrollment = null;
    q('#suForm').addEventListener('submit', async e => {
      e.preventDefault();
      const body = { token: q('#suTok').value.trim(), account: q('#suAcc').value.trim(), name: q('#suName').value.trim(), password: q('#suPwd').value };
      if (!body.token || !body.account || !body.name || !body.password) return err('请填写全部字段');
      if (body.password !== q('#suPwd2').value) return err('两次输入的口令不一致');
      const r = await act(q('#suNext'), () => API.post('/setup/begin', body, { quiet401: true }).catch(ex => { err(ex.message); return null; }));
      if (!r) return;
      enrollment = r.enrollment;
      q('#suSecret').textContent = r.secret.replace(/(.{4})/g, '$1 ').trim();
      q('#suUri').textContent = r.otpauth;
      q('#suSub').textContent = '第 2 步 / 共 2 步 · 绑定双因素认证';
      $$('.lg-pane', el).forEach(x => x.classList.toggle('on', x.dataset.p === 's2'));
      setTimeout(() => q('#suOtp input').focus(), 200);
    });
    const otps = $$('#suOtp input', el);
    const check = async () => {
      const v = otps.map(i => i.value).join('');
      if (v.length < 6) return;
      otps.forEach(i => { i.disabled = true; });
      try {
        const r = await API.post('/setup/complete', { enrollment, code: v }, { quiet401: true });
        q('#suOtp').classList.add('ok');
        await enter();
        el.classList.add('out'); setTimeout(() => el.remove(), 700);
        toast(`系统初始化完成，欢迎 ${esc(r.name)}。建议下一步：导入组织架构、配置策略、部署终端 Agent。`, { type: 'success', title: '初始化完成', dur: 6000 });
      } catch (ex) {
        otps.forEach(i => { i.disabled = false; i.value = ''; }); otps[0].focus();
        err(ex.message, '#suErr2');
      }
    };
    otps.forEach((inp, i) => inp.addEventListener('input', () => {
      const ds = inp.value.replace(/\D/g, '');
      if (!ds) { inp.value = ''; return; }
      ds.split('').forEach((c, k) => { if (otps[i + k]) otps[i + k].value = c; });
      (otps.find((x, k) => k > i && !x.value) || otps[Math.min(5, i + ds.length)]).focus();
      check();
    }));
  }

  /* 侧栏引擎状态与环境标识（来自服务端） */
  function renderSystem(sys) {
    const env = { production: ['生产环境', 'var(--success)', 'var(--success-weak)'], development: ['开发环境', 'var(--warning)', 'var(--warning-weak)'], demo: ['演示环境', 'var(--primary)', 'var(--primary-weak)'] }[sys.env] || ['生产环境'];
    const pill = $('.env-pill'); pill.lastChild.textContent = env[0]; pill.style.color = env[1]; pill.style.background = env[2];
    const t = $('.engine-text');
    t.querySelector('b').textContent = sys.nodes ? `检测集群 ${sys.nodesOnline} / ${sys.nodes} 节点在线` : '检测节点未接入';
    t.querySelector('small').textContent = `v${sys.version}`;
    $('.pulse-dot').style.background = sys.nodes && sys.nodesOnline === sys.nodes ? '' : 'var(--warning)';
  }

  /* 进入控制台：拉取引导数据 → 渲染外壳 → 建立实时推送 */
  async function enter() {
    const me = await API.get('/auth/me');
    if (me.pwdChange) { showPwdChange(me); return false; }
    const boot = await API.get('/bootstrap');
    D.load(boot);
    UI.me = boot.me;
    app.classList.remove('locked');
    renderUser(); buildNav(); renderWatermark(); renderNotes(); sysInfo = boot.system || {}; renderSystem(sysInfo);
    loadTasks();
    API.stream(UI.emit, () => { if (UI.me) API.get('/auth/me').catch(() => {}); });
    if (!location.hash) location.hash = '#/dashboard';
    route();
    return true;
  }
  function leave(reason) {
    API.closeStream();
    UI.runCleanups(); UI.closeAllLayers(); closePops();
    UI.me = null; tasks = []; D.reset(); renderWatermark();
    if (UI.ai) UI.ai.reset();
    $('#view').innerHTML = '';
    showLogin(reason);
  }
  API.onUnauthorized = () => { if (UI.me) leave('会话已过期或已在其他位置失效，请重新登录'); };
  // 会话期间口令到期：关闭控制台，进入改密流程
  API.onPwdChange = () => {
    if (!UI.me || $('#pwdc')) return;
    API.closeStream(); UI.runCleanups(); UI.closeAllLayers(); closePops();
    UI.me = null; D.reset(); $('#view').innerHTML = '';
    API.get('/auth/me').then(showPwdChange, () => showLogin());
  };
  async function logout() {
    const ok = await confirmDialog({ title: '退出登录', text: '退出后需要重新进行身份验证，未保存的更改将会丢失。', okText: '退出登录', danger: true });
    if (!ok) return;
    try { await API.post('/auth/logout'); } catch (e) { /* 会话可能已失效 */ }
    leave('您已安全退出，请重新登录');
  }

  /* 全局实时事件：新事件、通知、审批变化 */
  UI.on('incident', inc => {
    if (!D.incidents.some(i => i.id === inc.id)) { D.incidents.unshift(inc); if (D.incidents.length > 600) D.incidents.pop(); }
    UI.updateNav();
  });
  UI.on('note', n => UI.pushNote(n));
  // 检测节点心跳（运维权限可见）同步更新侧栏引擎状态
  let sysInfo = {};
  UI.on('nodes', m => { sysInfo.nodes = m.nodes.length; sysInfo.nodesOnline = m.nodes.filter(n => n.status !== 'offline').length; renderSystem(sysInfo); });
  UI.on('approvals.changed', async () => {
    if (!UI.can('approvals')) return;
    try { D.approvals = await API.get('/approvals'); UI.updateNav(); UI.emit('approvals.refreshed'); } catch (e) { /* 忽略 */ }
  });

  /* ---------- 初始化 ---------- */
  function init() {
    $$('[data-ic]').forEach(el => { el.outerHTML = ic(el.dataset.ic); });
    applyTheme(store.get('theme', 'system'));
    applyPrefs();
    renderNotes(); renderTasks();
    bindNav();
    if (store.get('collapsed', false)) app.classList.add('collapsed');
    $('#kbdHint').textContent = /Mac|iPhone|iPad/.test(navigator.platform) ? '⌘K' : 'Ctrl K';

    $('#menuBtn').addEventListener('click', () => {
      if (innerWidth <= 900) { app.classList.toggle('nav-open'); return; }
      app.classList.toggle('collapsed');
      store.set('collapsed', app.classList.contains('collapsed'));
      placeNavInd();
      setTimeout(() => { placeNavInd(); window.dispatchEvent(new Event('resize')); }, 320);
    });
    $('#sideOv').addEventListener('click', () => app.classList.remove('nav-open'));
    $('#themeBtn').addEventListener('click', toggleTheme);
    $('#searchBtn').addEventListener('click', openCmdk);
    $('#engineBox').addEventListener('click', () => { location.hash = UI.can('ops') ? '#/ops' : '#/dashboard'; });
    $('#bellBtn').addEventListener('click', e => { e.stopPropagation(); togglePop($('#notePop')); });
    $('#taskBtn').addEventListener('click', e => { e.stopPropagation(); renderTasks(); togglePop($('#taskPop')); });
    $('#userBtn').addEventListener('click', e => { e.stopPropagation(); togglePop($('#userPop')); });
    $('#notePop').addEventListener('click', e => {
      e.stopPropagation();
      if (e.target.closest('#readAll')) { D.notes.forEach(n => { n.unread = false; }); renderNotes(); API.post('/notes/read', { all: true }).catch(apiError); return; }
      const li = e.target.closest('.note');
      if (li) {
        const n = D.notes[+li.dataset.i];
        if (n.unread && n.id) API.post('/notes/read', { id: n.id }).catch(() => {});
        n.unread = false; renderNotes(); closePops(); location.hash = n.href;
      }
      if (e.target.closest('.pop-f')) closePops();
    });
    $('#taskPop').addEventListener('click', e => {
      e.stopPropagation();
      if (e.target.closest('#clrTask')) { API.del('/jobs').then(() => { tasks = tasks.filter(t => t.status === 'run'); renderTasks(); }).catch(apiError); return; }
      const d = e.target.closest('[data-dl]');
      if (d) API.download(`/api/v1/jobs/${encodeURIComponent(d.dataset.dl)}/download`);
    });
    $('#userPop').addEventListener('click', e => {
      e.stopPropagation();
      const r = e.target.closest('[data-role]');
      if (r) { closePops(); if (r.dataset.role !== UI.me.role) switchRole(r.dataset.role); return; }
      const b = e.target.closest('[data-u]'); if (!b) return;
      closePops();
      const u = b.dataset.u;
      if (u === 'appear') return openAppearance();
      if (u === 'pwd') return openPwdChange();
      if (u === 'logout') return logout();
    });
    document.addEventListener('click', closePops);

    document.addEventListener('keydown', e => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); cmdk ? closeCmdk() : openCmdk(); return; }
      if (e.key === '/' && !cmdk && UI.me && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); openCmdk(); return; }
      if (e.key === 'Escape') {
        if (cmdk) { closeCmdk(); return; }
        if (pops().some(p => p.classList.contains('show'))) { closePops(); return; }
        if (UI.closeTopLayer()) return;
        app.classList.remove('nav-open');
      }
    });

    // 按钮涟漪
    document.addEventListener('pointerdown', e => {
      const b = e.target.closest('.btn');
      if (!b || b.disabled || reduceMotion) return;
      const r = b.getBoundingClientRect(), s = Math.max(r.width, r.height);
      const sp = document.createElement('span');
      sp.className = 'ripple';
      sp.style.cssText = `width:${s}px;height:${s}px;left:${e.clientX - r.left - s / 2}px;top:${e.clientY - r.top - s / 2}px`;
      b.appendChild(sp); setTimeout(() => sp.remove(), 620);
    });

    window.addEventListener('hashchange', route);
    window.addEventListener('resize', placeNavInd);

    // 启动动画 → 恢复会话（Cookie）或进入登录
    const boot = $('#boot'), steps = ['正在连接管理服务…', '校验会话…', '加载控制台…'];
    let si = 0;
    const st = setInterval(() => { si = Math.min(steps.length - 1, si + 1); $('#bootStatus').textContent = steps[si]; }, 360);
    const minWait = new Promise(r => setTimeout(r, reduceMotion ? 50 : 1000));
    const session = API.get('/auth/me', { quiet401: true }).then(() => true, e => e.status === 401 ? false : Promise.reject(e));
    Promise.all([session, minWait]).then(async ([ok]) => {
      if (ok) { try { await enter(); } catch (e) { showLogin(); } return; }
      const cfg = await API.get('/auth/config').catch(() => ({}));
      cfg.setup ? showSetup() : showLogin();
    }).catch(e => {
      $('#bootStatus').textContent = '无法连接管理服务：' + e.message;
      $('#boot').classList.add('err');
      throw e;
    }).then(() => {
      clearInterval(st);
      boot.classList.add('done');
      setTimeout(() => boot.remove(), 700);
    }).catch(() => clearInterval(st));
  }
  init();
})();
