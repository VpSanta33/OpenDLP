/* 组织与权限：组织架构（AD 同步）、角色权限矩阵（三员分立校验）、管理员账号 */
(function () {
  'use strict';
  const { D, ic, $$, esc, fmtTime, relTime, avatar, toast, card, pagerHtml, openLayer, confirmDialog, act, seg, initSeg } = UI;

  const OPS = [['view', '查看'], ['op', '操作'], ['cfg', '配置'], ['exp', '导出']];
  const EST = { active: ['在职', 'b-success'], leaving: ['离职流程中', 'b-warning'], left: ['已离职', ''] };
  const SYS = ['iam', 'ops', 'settings'], SEC = ['incidents', 'ueba', 'policies', 'rules', 'discovery', 'approvals'];
  // 权限矩阵以服务端为准（编辑副本，保存时整体提交）
  let matrix = {};
  const initMatrix = () => { matrix = JSON.parse(JSON.stringify(D.perms || {})); };

  /* 敏感信息仅显示一次的弹窗（初始口令、MFA 绑定信息） */
  function secretModal(title, desc, rows) {
    openLayer('modal modal-sm', `<div class="md-head"><div><h2>${title}</h2><p>${desc}</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
      <div class="md-body">${rows.map(([k, v]) => `<div class="field"><label class="lbl">${k}</label><div class="secret-box">${esc(v)}</div></div>`).join('')}
        <div class="callout c-high">${ic('alert')}<div>关闭后将无法再次查看，请通过安全渠道交付给管理员本人。</div></div></div>
      <div class="md-foot"><span class="sp"></span><button class="btn btn-primary" data-close>我已妥善保存</button></div>`);
  }

  UI.pages.iam = {
    title: '组织与权限', icon: 'users',
    html() {
      return `
      <div class="page-head">
        <div><h1>组织与权限</h1><p>组织架构通过 CSV 导入维护，管理员角色遵循等保 2.0「三员分立」原则</p></div>
        <div class="head-actions">${seg('tab', [['org', '组织架构'], ['role', '角色权限'], ['adm', '管理员账号']], UI.params.get('tab') || 'org')}</div>
      </div>
      <div id="pane"></div>`;
    },
    mount(root) {
      initMatrix();
      const pane = root.querySelector('#pane');
      const show = v => { pane.classList.remove('swap'); void pane.offsetWidth; pane.classList.add('swap'); ({ org: orgPane, role: rolePane, adm: admPane })[v](pane); };
      initSeg(root, 'tab', show);
      show(UI.params.get('tab') || 'org');
    }
  };

  /* ---------- 组织架构 ---------- */
  function orgPane(el) {
    let dept = 'all', kw = '', page = 1; const per = 10;
    const cnt = d => D.employees.filter(e => d === 'all' || e.dept === d).length;
    el.innerHTML = `
      <div class="org-wrap">
        <section class="card org-tree">
          <header class="card-h"><div><h3>组织架构</h3><p>corp.example</p></div></header>
          <div class="card-b"><ul class="tree" id="tree">
            <li class="tr-root on" data-d="all">${ic('layers')}<span>全部员工</span><em>${cnt('all')}</em></li>
            ${D.depts.map((d, i) => `<li data-d="${d}" style="--i:${i}"><i class="tr-line"></i>${ic('folder')}<span>${d}</span><em>${cnt(d)}</em></li>`).join('')}
          </ul>
          <div class="sync-box"><div><b>${ic('upload')}组织架构导入</b><small id="syncT">CSV：工号,姓名,部门,职位,邮箱,状态,是否部门负责人</small></div><button class="btn btn-sm" id="sync" data-perm="iam:cfg">导入 CSV</button></div>
          <div class="progress sync-p" id="syncP"><i></i></div></div>
        </section>
        ${card('成员', `
          <div class="toolbar"><div class="search-box">${ic('search')}<input class="input" id="q" placeholder="搜索姓名、工号、职位…"></div><span class="sp"></span><span class="muted small" id="mc"></span></div>
          <div class="table-wrap"><table class="table"><thead><tr><th>姓名</th><th>工号</th><th>部门 / 职位</th><th>状态</th><th>终端</th><th>入职时间</th><th>身份源</th></tr></thead><tbody id="mem"></tbody></table></div>
          <div class="pager" id="pager"></div>`, { id: 'memCard', sub: '员工状态用于风险评分：离职流程中的员工外发行为风险加权' })}
      </div>`;
    const q = s => el.querySelector(s);
    function render() {
      const L = D.employees.filter(e => (dept === 'all' || e.dept === dept) && (!kw || (e.name + e.id + e.title).toLowerCase().includes(kw.toLowerCase())));
      const pages = Math.max(1, Math.ceil(L.length / per)); page = Math.min(page, pages);
      q('#mem').innerHTML = L.slice((page - 1) * per, page * per).map((e, i) => `<tr style="--i:${i}"><td><div class="u-cell">${avatar(e.name, 'sm')}<div><b>${esc(e.name)}</b><small>${e.email}</small></div></div></td>
        <td class="mono">${e.id}</td><td><div class="dt-cell">${e.dept}<small>${esc(e.title)}</small></div></td><td><span class="tag ${EST[e.status][1]}">${EST[e.status][0]}</span></td>
        <td class="mono muted">${e.status === 'left' ? '已回收' : e.host}</td><td class="muted">${new Date(e.joined).toISOString().slice(0, 10)}</td><td><span class="tag">${ic('upload')}CSV</span></td></tr>`).join('')
        || `<tr><td colspan="7"><div class="empty-st">${ic('users')}<p>${D.employees.length ? '没有匹配的成员' : '尚未导入组织架构，点击左侧「导入 CSV」'}</p></div></td></tr>`;
      q('#pager').innerHTML = pagerHtml(page, pages, L.length, per);
      q('#mc').textContent = `${dept === 'all' ? '全集团' : dept} · ${L.length} 人`;
    }
    q('#tree').addEventListener('click', e => { const li = e.target.closest('li'); if (!li) return; dept = li.dataset.d; page = 1; $$('#tree li', el).forEach(x => x.classList.toggle('on', x === li)); render(); });
    let t; q('#q').addEventListener('input', e => { clearTimeout(t); t = setTimeout(() => { kw = e.target.value.trim(); page = 1; render(); }, 160); });
    q('#pager').addEventListener('click', e => { const b = e.target.closest('[data-pg]'); if (b && !b.disabled) { page = +b.dataset.pg; render(); } });
    q('#sync').addEventListener('click', () => {
      const m = openLayer('modal', `<div class="md-head"><div><h2>导入组织架构</h2><p>CSV 列顺序：工号, 姓名, 部门, 职位, 邮箱, 状态（在职 / 离职中 / 已离职）, 是否部门负责人（是 / 否）。首行可为表头</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
        <div class="md-body"><div class="field"><label class="lbl">选择 CSV 文件 <span class="hint">UTF-8 编码</span></label><input type="file" class="input" id="csvFile" accept=".csv,text/csv" style="padding-top:6px"></div>
          <div class="field"><label class="lbl">或直接粘贴</label><textarea class="input mono" id="csvText" rows="7" style="width:100%" placeholder="工号,姓名,部门,职位,邮箱,状态,是否部门负责人&#10;E1001,张伟,研发中心,高级工程师,zhangwei@corp.example,在职,否"></textarea></div>
          <label class="set-row"><div><b>整体替换</b><small>开启后以本次导入为准，未出现在文件中的员工将被移除；关闭则按工号合并更新</small></div><span class="switch"><input type="checkbox" id="csvReplace"><span></span></span></label></div>
        <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('upload')}导入</button></div>`);
      const g = x => m.panel.querySelector(x);
      g('#csvFile').addEventListener('change', ev => { const f = ev.target.files[0]; if (f) f.text().then(t => { g('#csvText').value = t; }); });
      g('[data-ok]').addEventListener('click', ev => {
        const csv = g('#csvText').value.trim();
        if (!csv) { g('#csvText').classList.add('err'); return; }
        act(ev.currentTarget, () => API.post('/iam/employees/import', { csv, mode: g('#csvReplace').checked ? 'replace' : 'merge' }), r => {
          D.employees = r.employees; D.depts = r.depts; D.deptLeaders = r.deptLeaders;
          m.close(); UI.rerender();
          toast(`导入完成：新增 ${r.added} 人、更新 ${r.updated} 人，共 ${r.depts.length} 个部门`, { type: 'success', title: '组织架构已更新' });
        });
      });
    });
    render();
  }

  /* ---------- 角色权限 ---------- */
  function rolePane(el) {
    let cur = 'secadmin';
    const members = k => D.admins.filter(a => a.role === k).length;
    el.innerHTML = `
      <div class="role-wrap">
        <section class="card role-list"><header class="card-h"><div><h3>角色</h3><p>内置角色 4 个 · 自定义 ${D.roles.filter(r => !r.builtin).length} 个</p></div><div class="card-x"><button class="btn btn-sm" id="newRole" data-perm="iam:cfg">${ic('plus')}新建</button></div></header>
          <ul class="roles" id="roles"></ul></section>
        <section class="card role-main" id="rmain"></section>
      </div>`;
    const q = s => el.querySelector(s);
    function renderRoles() {
      q('#roles').innerHTML = D.roles.map((r, i) => `<li class="${r.key === cur ? 'on' : ''}" data-k="${r.key}" style="--i:${i}"><span class="role-dot b-${r.color}">${ic(r.builtin ? 'shield' : 'user')}</span><div><b>${r.name}</b><small>${esc(r.desc)}</small></div><em>${members(r.key)} 人</em></li>`).join('');
    }
    function conflict(m) {
      const sys = SYS.some(k => m[k].cfg), aud = m.audit && m.audit.view, sec = SEC.some(k => m[k].cfg);
      const c = [];
      if (sys && aud) c.push('系统配置权限与审计权限');
      if (sec && aud) c.push('安全策略配置权限与审计权限');
      return c;
    }
    function renderMain() {
      const r = D.roles.find(x => x.key === cur), m = matrix[cur], lock = r.builtin;
      const cf = conflict(m);
      q('#rmain').innerHTML = `
        <header class="card-h"><div><h3>${r.name} <span class="tag ${lock ? '' : 'b-info'}">${lock ? '内置' : '自定义'}</span></h3><p>${esc(r.desc)}</p></div>
          <div class="card-x">${lock ? `<span class="muted small">${ic('lock', 'ic-in')}内置角色权限不可修改</span><button class="btn btn-sm" id="dupRole" data-perm="iam:cfg">${ic('copy')}复制为自定义角色</button>` : `<button class="btn btn-sm btn-primary" id="saveRole" disabled>${ic('save')}保存</button>`}</div></header>
        <div class="card-b">
          <div class="callout ${cf.length ? 'c-critical' : ''}" id="cfBox">${ic(cf.length ? 'alert' : 'shield-check')}<div>${cf.length ? `<b>违反三员分立原则：</b>同一角色不应同时拥有${cf.join('、')}。等保 2.0 要求系统管理、安全管理与审计管理职责分离。` : '三员分立校验通过：该角色权限未出现职责冲突。'}</div></div>
          <div class="table-wrap pm-wrap"><table class="table pm-tbl"><thead><tr><th>功能模块</th>${OPS.map(([k, n]) => `<th class="c">${n}${lock ? '' : `<input type="checkbox" data-col="${k}" aria-label="全选${n}">`}</th>`).join('')}</tr></thead><tbody>
            ${UI.NAV.map(g => `<tr class="pm-g"><td colspan="5">${g.group}</td></tr>` + g.items.map(k => `<tr><td>${ic(UI.pages[k].icon, 'ic-in')}${UI.pages[k].title}</td>${OPS.map(([o]) => `<td class="c"><label class="pm-ck ${m[k][o] ? 'on' : ''}"><input type="checkbox" data-k="${k}" data-o="${o}" ${m[k][o] ? 'checked' : ''} ${lock ? 'disabled' : ''}><span>${ic('check')}</span></label></td>`).join('')}</tr>`).join('')).join('')}
          </tbody></table></div>
        </div>`;
      const box = q('#rmain');
      box.classList.remove('swap'); void box.offsetWidth; box.classList.add('swap');
      UI.applyPerms(box);
      if (!lock) {
        const save = q('#saveRole');
        const sync = () => {
          const c = conflict(m), cb = q('#cfBox');
          cb.className = 'callout ' + (c.length ? 'c-critical' : '');
          cb.innerHTML = `${ic(c.length ? 'alert' : 'shield-check')}<div>${c.length ? `<b>违反三员分立原则：</b>同一角色不应同时拥有${c.join('、')}。等保 2.0 要求系统管理、安全管理与审计管理职责分离。` : '三员分立校验通过：该角色权限未出现职责冲突。'}</div>`;
          if (c.length) { cb.classList.remove('shake'); void cb.offsetWidth; cb.classList.add('shake'); }
          save.disabled = false;
        };
        box.addEventListener('change', e => {
          const i = e.target;
          if (i.dataset.col) {
            UI.NAV.forEach(g => g.items.forEach(k => { m[k][i.dataset.col] = i.checked; if (i.dataset.col !== 'view' && i.checked) m[k].view = true; }));
            $$('input[data-k]', box).forEach(x => { x.checked = m[x.dataset.k][x.dataset.o]; x.parentElement.classList.toggle('on', x.checked); });
          } else if (i.dataset.k) {
            const k = i.dataset.k, o = i.dataset.o;
            m[k][o] = i.checked;
            if (o !== 'view' && i.checked) m[k].view = true;
            if (o === 'view' && !i.checked) OPS.forEach(([x]) => { m[k][x] = false; });
            $$(`input[data-k="${k}"]`, box).forEach(x => { x.checked = m[k][x.dataset.o]; x.parentElement.classList.toggle('on', x.checked); });
          }
          sync();
        });
        save.addEventListener('click', () => {
          if (conflict(m).length) { toast('当前权限组合违反三员分立原则，请调整后再保存', { type: 'error', title: '无法保存' }); return; }
          act(save, () => API.put(`/roles/${encodeURIComponent(r.key)}/perms`, m), x => {
            matrix[r.key] = x.perms; D.perms[r.key] = JSON.parse(JSON.stringify(x.perms));
            setTimeout(() => { save.disabled = true; });
            toast(`角色「${esc(r.name)}」权限已更新，${x.affected} 名管理员即时生效`, { type: 'success', title: '保存成功' });
          });
        });
      } else {
        q('#dupRole').addEventListener('click', () => createRole(r));
      }
    }
    function createRole(from) {
      const name = from ? from.name + '（副本）' : '新建角色 ' + (D.roles.length + 1);
      act(null, () => API.post('/roles', { name, from: from ? from.key : '' }), x => {
        D.roles.push(x.role); D.perms[x.role.key] = x.perms;
        matrix[x.role.key] = JSON.parse(JSON.stringify(x.perms));
        cur = x.role.key; renderRoles(); renderMain();
        toast(`已创建自定义角色「${esc(x.role.name)}」，可在右侧调整权限`, { type: 'success' });
      });
    }
    q('#roles').addEventListener('click', e => { const li = e.target.closest('li'); if (!li || li.dataset.k === cur) return; cur = li.dataset.k; $$('#roles li', el).forEach(x => x.classList.toggle('on', x === li)); renderMain(); });
    q('#newRole').addEventListener('click', () => createRole(null));
    renderRoles(); renderMain();
  }

  /* ---------- 管理员账号 ---------- */
  function admPane(el) {
    el.innerHTML = `
      <div class="mini-stats">
        <div class="mini"><span class="mini-ic mi-primary">${ic('users')}</span><div><span>管理员账号</span><b id="aN">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-success">${ic('shield-check')}</span><div><span>MFA 覆盖率</span><b id="aM">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-danger">${ic('lock')}</span><div><span>锁定账号</span><b id="aL">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-warning">${ic('key')}</span><div><span>密码将过期（7 天内）</span><b>1</b></div></div>
      </div>
      <div class="grid adm-grid">
        ${card('管理员账号', `<div class="table-wrap"><table class="table"><thead><tr><th>账号</th><th>角色</th><th>双因素认证</th><th>登录 IP</th><th>最近登录</th><th>状态</th><th></th></tr></thead><tbody id="adm"></tbody></table></div>`, { cls: 'span-2', extra: `<button class="btn btn-sm btn-primary" id="newAdm" data-perm="iam:cfg">${ic('plus')}新建管理员</button>` })}
        ${card('安全策略', `<ul class="pol-list">
          ${[['key', '密码复杂度', '≥ 12 位，含大小写字母、数字与符号'], ['clock', '密码有效期', '90 天强制更换，不得与近 5 次重复'], ['lock', '登录失败锁定', '连续 5 次失败锁定 15 分钟'], ['shield-check', '双因素认证', '所有管理员强制启用 TOTP / 企业微信'], ['globe', '登录 IP 白名单', '仅允许 10.0.8.0/24 运维网段'], ['logout', '会话超时', '无操作 30 分钟自动退出']].map(([i, t, d]) => `<li>${ic(i)}<div><b>${t}</b><small>${d}</small></div></li>`).join('')}</ul>`, { sub: '符合等保 2.0 身份鉴别要求' })}
      </div>`;
    const q = s => el.querySelector(s);
    function render() {
      q('#aN').textContent = D.admins.length;
      q('#aM').innerHTML = Math.round(D.admins.filter(a => a.mfa).length / D.admins.length * 100) + '<small>%</small>';
      q('#aL').textContent = D.admins.filter(a => a.status === 'locked').length;
      q('#adm').innerHTML = D.admins.map((a, i) => { const r = UI.ROLE[a.role] || { color: '', name: a.role }; return `<tr style="--i:${i}" data-acc="${a.acc}"><td><div class="u-cell">${avatar(a.name, 'sm')}<div><b>${esc(a.name)}</b><small class="mono">${a.acc}</small></div></div></td>
        <td><span class="tag b-${r.color}">${r.name}</span></td>
        <td>${a.mfa ? `<span class="ok-t">${ic('shield-check', 'ic-in')}已启用</span>` : `<span class="warn-c">${ic('alert', 'ic-in')}未启用</span>`}</td>
        <td class="mono muted">${a.ip}</td><td class="muted">${relTime(a.last)}</td>
        <td>${a.status === 'locked' ? '<span class="status st-pending">已锁定</span>' : '<span class="status st-resolved">正常</span>'}</td>
        <td class="acts">${a.status === 'locked' ? `<button class="btn btn-sm" data-a="unlock">${ic('unlock')}解锁</button>` : a.mfa ? `<button class="btn btn-sm btn-ghost" data-a="mfa">重置 MFA</button>` : `<button class="btn btn-sm" data-a="force">${ic('shield')}强制启用 MFA</button>`}${a.acc === UI.me.acc ? '<span class="tag">当前</span>' : `<button class="icon-btn sm" data-a="dis" title="禁用">${ic('ban')}</button>`}</td></tr>`; }).join('');
    }
    q('#adm').addEventListener('click', async e => {
      const b = e.target.closest('[data-a]'); if (!b) return;
      const a = D.admins.find(x => x.acc === b.closest('tr').dataset.acc), k = b.dataset.a;
      const run = action => act(b, () => API.post(`/admins/${encodeURIComponent(a.acc)}/${action}`), r => {
        Object.assign(a, r.admin); render();
        if (r.otpauth) secretModal('双因素认证绑定信息', `${esc(a.name)} 需使用身份验证器扫描或导入以下地址，原有会话已全部下线`, [['otpauth URI', r.otpauth]]);
        return r;
      });
      if (k === 'unlock') run('unlock').then(r => r && toast(`账号 ${esc(a.acc)} 已解锁`, { type: 'success' }));
      else if (k === 'force') run('force-mfa');
      else if (k === 'mfa') { if (await confirmDialog({ title: '重置双因素认证', text: `${esc(a.name)} 需要重新绑定身份验证器，现有会话将全部下线。`, okText: '确认重置' })) run('reset-mfa'); }
      else if (k === 'dis') { if (await confirmDialog({ title: `禁用管理员 ${esc(a.acc)}`, text: '禁用后该账号将立即下线且无法登录，相关操作记录仍会保留。', okText: '确认禁用', danger: true })) run('disable').then(r => r && toast(`账号 ${esc(a.acc)} 已禁用并强制下线`, { type: 'warning' })); }
    });
    q('#newAdm').addEventListener('click', () => {
      const { panel, close } = openLayer('modal', `
        <div class="md-head"><div><h2>新建管理员</h2><p>系统将生成随机初始口令与 MFA 绑定信息（仅显示一次）</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
        <div class="md-body">
          <div class="grid g2" style="margin-bottom:0">
            <div class="field"><label class="lbl">账号 <em>*</em></label><input class="input" id="nAcc" placeholder="例如 sec_zhangsan"><div class="field-err" id="nAccErr"></div></div>
            <div class="field"><label class="lbl">姓名 <em>*</em></label><input class="input" id="nName" placeholder="从 AD 选择或手动输入"></div>
          </div>
          <div class="field"><label class="lbl">角色</label><div class="opt-grid" id="nRole">${D.roles.filter(r => r.key !== 'super').map((r, i) => `<button class="opt ${i === 1 ? 'on' : ''}" data-r="${r.key}">${ic(r.builtin ? 'shield' : 'user')}${r.name}</button>`).join('')}</div></div>
          <div class="field"><label class="lbl">登录 IP 限制 <span class="hint">IP 或 CIDR 网段</span></label><input class="input" id="nIp" value="10.0.8.0/24"></div>
          <label class="set-row"><div><b>强制双因素认证</b><small>安全策略要求，不可关闭</small></div><span class="switch"><input type="checkbox" checked disabled><span></span></span></label>
        </div>
        <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('check')}创建</button></div>`);
      const g = s => panel.querySelector(s);
      g('#nRole').addEventListener('click', e => { const b = e.target.closest('.opt'); if (b) $$('.opt', panel).forEach(x => x.classList.toggle('on', x === b)); });
      g('[data-ok]').addEventListener('click', e => {
        const acc = g('#nAcc').value.trim(), name = g('#nName').value.trim(), err = g('#nAccErr');
        const bad = !/^[a-z][a-z0-9_]{2,23}$/.test(acc) ? '账号需以小写字母开头，3-24 位小写字母、数字或下划线' : D.admins.some(a => a.acc === acc) ? '该账号已存在' : '';
        g('#nAcc').classList.toggle('err', !!bad); err.textContent = bad; err.classList.toggle('show', !!bad);
        g('#nName').classList.toggle('err', !name);
        if (bad || !name) return;
        act(e.currentTarget, () => API.post('/admins', { acc, name, role: g('#nRole .opt.on').dataset.r, ip: g('#nIp').value.trim() }), r => {
          D.admins.push(r.admin);
          close(); render();
          secretModal(`管理员 ${esc(r.admin.name)} 已创建`, '请将初始口令与 MFA 绑定信息安全交付，首次登录后应立即修改口令', [['账号', r.admin.acc], ['初始口令', r.initialPassword], ['MFA 绑定（otpauth URI）', r.otpauth]]);
        });
      });
    });
    render();
  }
})();
