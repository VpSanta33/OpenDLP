/* 终端管理 */
(function () {
  'use strict';
  const { D, ic, $$, esc, fmt, fmtTime, relTime, countUp, toast, seg, initSeg, sevBadge, openLayer, confirmDialog, act } = UI;
  const EPST = { online: '在线', offline: '离线', warning: '防护异常' };
  const MODS = ['文件外发监控', '网络流量检测', 'USB 设备管控', '打印审计', '屏幕水印', '防卸载保护'];

  function epCard(e, i) {
    const latest = e.agent === '3.2.1';
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
    const badMod = e.status === 'warning' ? 5 : -1;
    const html = `
      <div class="dr-head">
        <div class="dr-meta"><span class="os os-${e.osKey}" style="width:30px;height:30px;font-size:9.5px">${e.osShort}</span><span class="st-dot ${e.status}"></span><span class="muted small">${EPST[e.status]}</span></div>
        <h2 class="mono">${e.host}</h2><p>${esc(e.user)} · ${e.dept} · ${e.os}</p>
        <button class="icon-btn dr-close" data-close aria-label="关闭">${ic('x')}</button>
      </div>
      <div class="dr-body">
        ${e.status === 'warning' ? `<div class="callout c-high">${ic('alert')}<div>检测到 <b>防卸载保护模块</b> 异常停止，可能存在 Agent 被篡改风险，建议立即远程修复或隔离终端。</div></div>` : ''}
        <div class="kv">${[['IP 地址', e.ip], ['Agent 版本', 'v' + e.agent], ['最后心跳', e.status === 'online' ? fmtTime(Date.now()) : fmtTime(e.lastSeen)], ['已下发策略', D.policies.filter(p => p.enabled).length + ' 条'], ['CPU 占用', e.cpu + '%'], ['磁盘使用', e.disk + '%']].map(([k, v]) => `<div><span>${k}</span><b>${v}</b></div>`).join('')}</div>
        <h4 class="sec-t">防护模块状态</h4>
        <div class="mods">${MODS.map((m, k) => {
          const bad = k === badMod || e.status === 'offline';
          return `<div class="mod ${bad ? 'bad' : ''}">${ic(bad ? 'alert' : 'shield-check')}${m}<em>${e.status === 'offline' ? '未知' : bad ? '已停止' : '运行中'}</em></div>`;
        }).join('')}</div>
        <h4 class="sec-t">近期事件 <small>${evs.length} 起</small></h4>
        ${evs.length ? `<ul class="mini-list">${evs.map(i => `<li data-inc="${i.id}">${sevBadge(i.severity)}<span>${esc(i.file)} · ${D.chMap[i.channel].name}</span><time class="muted small">${relTime(i.ts)}</time></li>`).join('')}</ul>` : `<div class="empty-st" style="padding:24px 0">${ic('shield-check')}<p>近 7 天无风险事件</p></div>`}
      </div>
      <div class="dr-foot">
        <button class="btn" data-a="scan" data-perm="endpoints:op" ${e.status === 'offline' ? 'disabled' : ''}>${ic('file-search')}远程扫描</button>
        <button class="btn" data-a="push" data-perm="endpoints:op" ${e.status === 'offline' ? 'disabled' : ''}>${ic('send')}推送策略</button>
        ${e.isolated ? `<button class="btn btn-primary" data-a="release" data-perm="endpoints:op">${ic('unlock')}解除隔离</button>`
          : `<button class="btn btn-danger" data-a="iso" data-perm="endpoints:op" ${e.status === 'offline' ? 'disabled' : ''}>${ic('lock')}隔离终端</button>`}
      </div>`;
    const { panel, close } = openLayer('drawer', html);
    UI.applyPerms(panel);
    panel.addEventListener('click', ev => {
      const li = ev.target.closest('[data-inc]');
      if (li) { close(); setTimeout(() => UI.openIncident(li.dataset.inc), 250); return; }
      const b = ev.target.closest('[data-a]'); if (!b || b.disabled) return;
      const cmd = action => API.post(`/endpoints/${encodeURIComponent(e.id)}/actions`, { action });
      const sent = r => r.offline ? '终端当前离线，指令将在其上线后执行' : '终端将在下次心跳（约 1 分钟内）领取执行';
      if (b.dataset.a === 'push') act(b, () => cmd('push'), r => toast(`已向 ${esc(e.host)} 下发策略同步指令（${r.policies} 条启用策略），${sent(r)}`, { type: 'success', title: '指令已下发' }));
      if (b.dataset.a === 'scan') act(b, () => cmd('scan'), r => toast(`已向 ${esc(e.host)} 下发本地敏感文件扫描指令，${sent(r)}`, { type: 'info', title: '指令已下发' }));
      if (b.dataset.a === 'release') act(b, () => cmd('release'), r => { Object.assign(e, r.endpoint); close(); toast(`${esc(e.host)} 已解除网络隔离`, { type: 'success' }); onChange && onChange(); });
      if (b.dataset.a === 'iso') {
        confirmDialog({ title: `隔离终端 ${esc(e.host)}？`, text: '隔离后该终端将断开除管理服务器外的所有网络连接，用户将收到隔离通知。此操作会记录到审计日志。', okText: '确认隔离', danger: true })
          .then(ok => ok && act(b, () => cmd('isolate'), r => { Object.assign(e, r.endpoint); close(); toast(`${esc(e.host)} 已进入网络隔离状态`, { type: 'warning', title: '终端已隔离' }); onChange && onChange(); }));
      }
    });
  }

  UI.pages.endpoints = {
    title: '终端管理', icon: 'monitor',
    html() {
      const by = st => D.endpoints.filter(e => e.status === st).length;
      const stats = [['已接入终端', D.endpoints.length, 'monitor', 'primary'], ['在线', by('online'), 'check', 'success'], ['离线', by('offline'), 'clock', 'muted'], ['防护异常', by('warning'), 'alert', 'warning']];
      return `
      <div class="page-head">
        <div><h1>终端管理</h1><p>管理已部署 DLP Agent 的办公终端，监控防护状态与策略同步情况</p></div>
        <div class="head-actions"><button class="btn" data-act="export" data-perm="endpoints:exp">${ic('download')}导出清单</button><button class="btn" data-act="upgrade" data-perm="endpoints:op">${ic('refresh')}批量升级 Agent</button><button class="btn btn-primary" data-act="deploy" data-perm="endpoints:cfg">${ic('plus')}终端接入</button></div>
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
      q('[data-act="upgrade"]').addEventListener('click', async e => {
        const latest = D.endpoints.map(x => x.agent).sort((a, b2) => a.localeCompare(b2, undefined, { numeric: true })).pop();
        const n = D.endpoints.filter(x => x.agent !== latest && x.status !== 'offline').length;
        if (!n) { toast('所有在线终端均已是最新版本', { type: 'info' }); return; }
        const ok = await confirmDialog({ title: '批量升级 Agent', text: `将向版本落后的 ${n} 台终端下发升级指令（目标为当前已接入终端中的最高版本），终端在下次心跳时执行。`, okText: '开始升级' });
        if (ok) act(e.target.closest('button'), () => API.post('/endpoints/batch-upgrade'), r => {
          toast(`已向 ${r.upgraded} 台终端下发升级至 v${esc(r.version)} 的指令`, { type: 'success', title: '升级指令已下发' });
        });
      });
      q('[data-act="export"]').addEventListener('click', () => UI.task(() => API.post('/exports', { kind: 'endpoints' })));
      q('[data-act="deploy"]').addEventListener('click', e => act(e.currentTarget, () => API.post('/endpoints/deploy-token'), r => {
        const base = location.origin;
        UI.openLayer('modal', `<div class="md-head"><div><h2>终端接入</h2><p>在终端 Agent / 网关的配置中填写以下参数</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
          <div class="md-body">
            <div class="field"><label class="lbl">心跳与指令领取（每 60 秒）</label><div class="secret-box">POST ${esc(base + r.heartbeat)}</div></div>
            <div class="field"><label class="lbl">检测结果上报</label><div class="secret-box">POST ${esc(base + r.detections)}</div></div>
            <div class="field"><label class="lbl">认证请求头</label><div class="secret-box">Authorization: Bearer ${esc(r.token)}</div></div>
            <div class="callout c-high">${ic('alert')}<div>令牌拥有上报权限，请通过安全渠道下发到终端配置，切勿写入公开文档。查看令牌的操作已记录审计日志。</div></div>
          </div><div class="md-foot"><span class="sp"></span><button class="btn btn-primary" data-close>完成</button></div>`);
      }));
      render();
    }
  };
})();
