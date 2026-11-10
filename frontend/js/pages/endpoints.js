/* 终端管理 */
(function () {
  'use strict';
  const { D, ic, $$, esc, fmt, fmtTime, relTime, countUp, toast, seg, initSeg, sevBadge, openLayer, confirmDialog, act } = UI;
  const EPST = { online: '在线', offline: '离线', warning: '上报异常' };
  const CMD = { push: '推送策略', scan: '远程扫描', isolate: '隔离终端', release: '解除隔离' }; // 历史指令可能包含后两种
  const CST = { pending: ['待领取', ''], delivered: ['执行中', 'b-primary'], done: ['已完成', 'b-success'], failed: ['失败', 'b-danger'] };
  const cmdName = a => CMD[a] || (a.startsWith('upgrade:') ? '升级至 v' + a.slice(8) : a);
  // 语义化版本比较
  const verCmp = (a, b) => { const x = String(a || '').split('.').map(Number), y = String(b || '').split('.').map(Number); for (let i = 0; i < 3; i++) { if ((x[i] || 0) !== (y[i] || 0)) return (x[i] || 0) - (y[i] || 0); } return 0; };
  const latestAgent = () => D.endpoints.reduce((m, e) => (verCmp(e.agent, m) > 0 ? e.agent : m), '');

  function epCard(e, i) {
    const latest = verCmp(e.agent, latestAgent()) >= 0;
    return `<article class="ep ${e.status === 'offline' ? 'st-off' : ''}" data-id="${e.id}" style="--i:${i}" tabindex="0">
      <div class="ep-top"><span class="os os-${e.osKey}">${e.osShort}</span>
        <div class="ep-name"><b>${e.host}</b><span>${esc(e.user)} · ${e.dept}</span></div>
        <span class="st-dot ${e.status}" data-tip="${EPST[e.status]}"></span></div>
      <div class="ep-kv">
        <div><span>IP 地址</span><b class="mono">${e.ip}</b></div>
        <div><span>操作系统</span><b>${e.os}</b></div>
        <div><span>Agent 版本</span><b>v${e.agent}${latest ? '' : ' <em class="warn-t">可升级</em>'}</b></div>
        <div><span>最后在线</span><b>${e.status === 'online' ? '<span class="ok-t">当前在线</span>' : relTime(e.lastSeen)}</b></div>
      </div>
      <div class="ep-meters">
        <div><span>CPU</span><div class="meter"><i class="${e.cpu > 75 ? 'hot' : ''}" style="--w:${e.cpu}%;--d:${0.15 + i * 0.03}s"></i></div><em>${e.cpu}%</em></div>
        <div><span>内存</span><div class="meter"><i class="${e.mem > 80 ? 'warm' : ''}" style="--w:${e.mem}%;--d:${0.2 + i * 0.03}s"></i></div><em>${e.mem}%</em></div>
      </div>
    </article>`;
  }

  function openEndpoint(e, onChange) {
    const evs = D.incidents.filter(i => i.host === e.host).slice(0, 5);
    const html = `
      <div class="dr-head">
        <div class="dr-meta"><span class="os os-${e.osKey}" style="width:30px;height:30px;font-size:9.5px">${e.osShort}</span><span class="st-dot ${e.status}"></span><span class="muted small">${EPST[e.status]}</span></div>
        <h2 class="mono">${e.host}</h2><p>${esc(e.user)} · ${e.dept} · ${e.os}</p>
        <button class="icon-btn dr-close" data-close aria-label="关闭">${ic('x')}</button>
      </div>
      <div class="dr-body">
        ${e.status === 'warning' ? `<div class="callout c-high">${ic('alert')}<div>Agent 上报异常：与控制台通信失败，或本地离线队列中有待补报的检测结果。请检查终端网络与 Agent 日志。</div></div>` : ''}
        ${e.strict ? `<div class="callout c-high">${ic('shield')}<div>该终端处于<b>严格管控</b>模式：审计策略升级为阻断，未命中策略的敏感文件也将生成事件。</div></div>` : ''}
        <div class="kv">${[['IP 地址', esc(e.ip || '—')], ['Agent 版本', 'v' + esc(e.agent || '—')], ['最后心跳', e.lastSeen ? fmtTime(e.lastSeen) : '—'],
          ['接入方式', e.enrolled ? '<span class="ok-t">独立凭据</span>' : '共享令牌'],
          ['策略版本', e.policyVersion ? `<span class="mono">${esc(e.policyVersion.slice(0, 8))}</span> ${e.policySynced ? '<span class="ok-t">最新</span>' : '<span class="warn-c">待同步</span>'}` : '—'],
          ['CPU / 内存 / 磁盘', `${e.cpu || 0}% / ${e.mem || 0}% / ${e.disk || 0}%`]].map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join('')}</div>
        <h4 class="sec-t">指令记录</h4>
        <ul class="mini-list" id="epCmds"><li class="muted small">加载中…</li></ul>
        <h4 class="sec-t">近期事件 <small>${evs.length} 起</small></h4>
        ${evs.length ? `<ul class="mini-list">${evs.map(i => `<li data-inc="${i.id}">${sevBadge(i.severity)}<span>${esc(i.file)} · ${D.chMap[i.channel].name}</span><time class="muted small">${relTime(i.ts)}</time></li>`).join('')}</ul>` : `<div class="empty-st" style="padding:24px 0">${ic('shield-check')}<p>近 7 天无风险事件</p></div>`}
      </div>
      <div class="dr-foot">
        <button class="btn" data-a="scan" data-perm="endpoints:op" ${e.status === 'offline' ? 'disabled' : ''}>${ic('file-search')}远程扫描</button>
        <button class="btn" data-a="push" data-perm="endpoints:op" ${e.status === 'offline' ? 'disabled' : ''}>${ic('send')}推送策略</button>
        ${e.enrolled ? `<button class="icon-btn" data-a="revoke" data-perm="endpoints:cfg" title="吊销 Agent 凭据">${ic('ban')}</button>` : ''}
      </div>`;
    const { panel, close } = openLayer('drawer', html);
    UI.applyPerms(panel);
    const loadCmds = () => API.get(`/endpoints/${encodeURIComponent(e.id)}/commands`).then(list => {
      const box = panel.querySelector('#epCmds'); if (!box) return;
      box.innerHTML = list.length ? list.slice(0, 8).map(c => `<li title="${esc(c.result || '')}"><span class="tag ${CST[c.status][1]}">${CST[c.status][0]}</span><span>${esc(cmdName(c.action))}${c.result ? `<small class="muted" style="display:block">${esc(c.result)}</small>` : ''}</span><time class="muted small">${relTime(c.finished || c.created)}</time></li>`).join('')
        : '<li class="muted small">暂无指令</li>';
    }).catch(() => { const box = panel.querySelector('#epCmds'); if (box) box.innerHTML = '<li class="muted small">无权查看</li>'; });
    loadCmds();
    panel.addEventListener('click', ev => {
      const li = ev.target.closest('[data-inc]');
      if (li) { close(); setTimeout(() => UI.openIncident(li.dataset.inc), 250); return; }
      const b = ev.target.closest('[data-a]'); if (!b || b.disabled) return;
      const cmd = action => API.post(`/endpoints/${encodeURIComponent(e.id)}/actions`, { action });
      const sent = r => r.offline ? '终端当前离线，指令将在其上线后执行' : '终端将在下次心跳（约 1 分钟内）领取执行';
      if (b.dataset.a === 'revoke') {
        confirmDialog({ title: `吊销 ${esc(e.host)} 的 Agent 凭据？`, text: '吊销后该终端的请求将被拒绝；若终端仍保留注册令牌，会自动重新注册并获得新凭据。如需彻底停用，请同时轮换服务端注册令牌。', okText: '确认吊销', danger: true })
          .then(ok => ok && act(b, () => API.post(`/endpoints/${encodeURIComponent(e.id)}/revoke`), r => { Object.assign(e, r); close(); toast(`${esc(e.host)} 的 Agent 凭据已吊销`, { type: 'warning' }); onChange && onChange(); }));
        return;
      }
      if (b.dataset.a === 'push') act(b, () => cmd('push'), r => (loadCmds(), toast(`已向 ${esc(e.host)} 下发策略同步指令（${r.policies} 条启用策略），${sent(r)}`, { type: 'success', title: '指令已下发' })));
      if (b.dataset.a === 'scan') act(b, () => cmd('scan'), r => (loadCmds(), toast(`已向 ${esc(e.host)} 下发本地敏感文件扫描指令（U 盘与监控目录），${sent(r)}`, { type: 'info', title: '指令已下发' })));
    });
  }

  UI.pages.endpoints = {
    title: '终端管理', icon: 'monitor',
    html() {
      const by = st => D.endpoints.filter(e => e.status === st).length;
      const stats = [['已接入终端', D.endpoints.length, 'monitor', 'primary'], ['在线', by('online'), 'check', 'success'], ['离线', by('offline'), 'clock', 'muted'], ['上报异常', by('warning'), 'alert', 'warning']];
      return `
      <div class="page-head">
        <div><h1>终端管理</h1><p>查看已接入的终端 Agent、策略同步情况与指令执行结果</p></div>
        <div class="head-actions"><button class="btn" data-act="export" data-perm="endpoints:exp">${ic('download')}导出清单</button><button class="btn btn-primary" data-act="deploy" data-perm="endpoints:cfg">${ic('plus')}终端接入</button></div>
      </div>
      <div class="mini-stats">${stats.map(s => `<div class="mini"><span class="mini-ic mi-${s[3]}">${ic(s[2])}</span><div><span>${s[0]}</span><b data-count="${s[1]}">0</b></div></div>`).join('')}</div>
      <div class="toolbar">
        <div class="search-box">${ic('search')}<input class="input" id="eq" placeholder="搜索主机名、用户、IP…"></div>
        ${seg('es', [['all', '全部'], ['online', '在线'], ['offline', '离线'], ['warning', '异常']], 'all')}
        <select class="input" id="eos" aria-label="操作系统"><option value="all">全部系统</option><option value="win">Windows</option><option value="mac">macOS</option><option value="uos">统信 UOS</option><option value="kylin">银河麒麟</option></select>
        <span class="sp"></span><span class="muted" id="epCnt"></span>
      </div>
      <div class="ep-grid" id="epGrid"></div>`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      const f = { q: '', st: 'all', os: 'all' };
      root.querySelectorAll('[data-count]').forEach(el => countUp(el, +el.dataset.count, { from: 0 }));
      function render() {
        const L = D.endpoints.filter(e => (f.st === 'all' || e.status === f.st) && (f.os === 'all' || e.osKey === f.os) &&
          (!f.q || (e.host + e.user + e.ip + e.dept).toLowerCase().includes(f.q.toLowerCase())));
        q('#epGrid').innerHTML = L.length ? L.map(epCard).join('') : `<div class="empty-st" style="grid-column:1/-1">${ic('monitor')}<p>${D.endpoints.length ? '没有符合条件的终端' : '尚无终端接入。点击右上角「终端接入」获取 Agent 上报地址与令牌'}</p></div>`;
        q('#epCnt').textContent = `显示 ${L.length} 台`;
      }
      initSeg(root, 'es', v => { f.st = v; render(); });
      q('#eos').addEventListener('change', e => { f.os = e.target.value; render(); });
      let t; q('#eq').addEventListener('input', e => { clearTimeout(t); t = setTimeout(() => { f.q = e.target.value.trim(); render(); }, 160); });
      q('#epGrid').addEventListener('click', e => { const c = e.target.closest('.ep'); if (c) openEndpoint(D.endpoints.find(x => x.id === c.dataset.id), render); });
      q('#epGrid').addEventListener('keydown', e => { if (e.key === 'Enter') { const c = e.target.closest('.ep'); if (c) openEndpoint(D.endpoints.find(x => x.id === c.dataset.id)); } });
      q('[data-act="export"]').addEventListener('click', () => UI.task(() => API.post('/exports', { kind: 'endpoints' })));
      q('[data-act="deploy"]').addEventListener('click', e => act(e.currentTarget, () => API.post('/endpoints/deploy-token'), r => {
        const base = r.server || location.origin;
        const { panel } = UI.openLayer('modal', `<div class="md-head"><div><h2>终端接入</h2><p>部署 OpenDLP Agent（Windows / macOS / Linux，含统信 UOS、麒麟与龙芯平台）</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
          <div class="md-body">
            ${seg('dpOs', [['linux', 'Linux'], ['mac', 'macOS'], ['win', 'Windows'], ['api', '第三方接入']], 'linux')}
            <div id="dpBody" style="margin-top:14px"></div>
            <div class="callout c-high" style="margin-top:14px">${ic('alert')}<div>注册令牌只用于首次注册，终端随后使用独立凭据（可单独吊销）。请通过软件分发平台或安全渠道下发，切勿写入公开文档；查看令牌的操作已记录审计日志。</div></div>
          </div><div class="md-foot"><span class="sp"></span><button class="btn btn-primary" data-close>完成</button></div>`);
        const box = (t, v) => `<div class="field"><label class="lbl">${t}</label><div class="secret-box small" style="white-space:pre-wrap">${esc(v)}</div></div>`;
        const cfg = JSON.stringify({ server: base, enrollToken: r.token }, null, 2);
        const views = {
          linux: box('1. 配置文件 /etc/opendlp/agent.json（权限 0600）', cfg) + box('2. 安装为 systemd 服务（deploy/agent/opendlp-agent.service）', 'sudo install -m 0755 opendlp-agent-linux-amd64 /usr/local/bin/opendlp-agent\nsudo install -m 0644 opendlp-agent.service /etc/systemd/system/\nsudo systemctl daemon-reload && sudo systemctl enable --now opendlp-agent\nsudo opendlp-agent status'),
          mac: box('1. 配置文件 /Library/Application Support/OpenDLP/agent.json（权限 0600）', cfg) + box('2. 安装为 launchd 守护进程（deploy/agent/com.opendlp.agent.plist）', 'sudo install -m 0755 opendlp-agent-darwin-arm64 /usr/local/bin/opendlp-agent\nsudo install -m 0644 com.opendlp.agent.plist /Library/LaunchDaemons/\nsudo launchctl bootstrap system /Library/LaunchDaemons/com.opendlp.agent.plist') + '<p class="muted small">需通过 MDM 为 Agent 授予「完全磁盘访问权限」，否则无法读取 U 盘与用户目录。</p>',
          win: box('以管理员身份运行 PowerShell（deploy/agent/install-windows.ps1）', `.\\install-windows.ps1 -Server ${base} -Token ${r.token}`),
          api: box('心跳与指令领取（每 60 秒）', 'POST ' + location.origin + r.heartbeat) + box('检测结果上报', 'POST ' + location.origin + r.detections) + box('认证请求头', 'Authorization: Bearer ' + r.token) + '<p class="muted small">适用于网关、邮件 MTA 等第三方系统以共享令牌接入；终端请优先使用 OpenDLP Agent。</p>'
        };
        const show = k => { panel.querySelector('#dpBody').innerHTML = views[k] + (k !== 'api' && !r.server ? '<p class="muted small">提示：可在「系统设置 → 告警通知 → 控制台访问地址」中填写终端可访问的地址。</p>' : ''); };
        initSeg(panel, 'dpOs', show); show('linux');
      }));
      render();
    }
  };
})();
