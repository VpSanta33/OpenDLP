/* 运维与集成：检测集群、服务健康、第三方集成、授权许可、规则库升级 */
(function () {
  'use strict';
  const { D, C, ic, $$, fmt, esc, toast, card, openLayer, act, countUp } = UI;

  const IST = { ok: ['已连接', 'b-success'], warn: ['异常', 'b-warning'], off: ['未配置', ''] };

  UI.pages.ops = {
    title: '运维与集成', icon: 'server',
    html() {
      const used = D.fleet.deployed, total = D.fleet.licensed, S = D.settings || {};
      const exp = S.licenseExpiry ? Math.ceil((new Date(S.licenseExpiry + 'T23:59:59') - Date.now()) / 864e5) : null;
      return `
      <div class="page-head">
        <div><h1>运维与集成</h1><p>检测集群运行状态、平台服务健康、第三方系统集成与授权许可</p></div>
        <div class="head-actions"><span class="pill" id="envPill2"></span><button class="btn" id="diag" data-perm="ops:cfg">${ic('activity')}一键诊断</button></div>
      </div>
      <div class="kpis ops-k">
        <div class="kpi" style="--accent:var(--c1)"><div class="kpi-top"><span class="kpi-label">集群吞吐</span><span class="kpi-ic">${ic('activity')}</span></div><span class="kpi-val"><span id="qps">0</span><small>次/秒</small></span><div class="kpi-foot"><span class="muted small" id="nodeCnt">${D.nodes.length} 个检测节点</span><div class="spark" id="spQ"></div></div></div>
        <div class="kpi" style="--accent:var(--c2)"><div class="kpi-top"><span class="kpi-label">平均检测时延</span><span class="kpi-ic">${ic('clock')}</span></div><span class="kpi-val"><span id="lat">0</span><small>ms</small></span><div class="kpi-foot"><span class="muted small">在线节点均值</span><div class="spark" id="spL"></div></div></div>
        <div class="kpi" style="--accent:var(--c3)"><div class="kpi-top"><span class="kpi-label">终端授权</span><span class="kpi-ic">${ic('monitor')}</span></div><span class="kpi-val"><span data-n="${used}">0</span><small>/ ${total ? fmt(total) : '未配置'}</small></span><div class="kpi-foot" style="display:block">${total ? `<div class="meter" style="margin-top:10px"><i class="${used / total > .9 ? 'hot' : 'warm'}" style="--w:${Math.min(100, used / total * 100)}%"></i></div>` : '<span class="muted small">在「系统设置 → 授权许可」中填写</span>'}</div></div>
        <div class="kpi" style="--accent:var(--c4)"><div class="kpi-top"><span class="kpi-label">许可有效期</span><span class="kpi-ic">${ic('key')}</span></div><span class="kpi-val">${exp == null ? '<span style="font-size:20px">未配置</span>' : `<span data-n="${Math.max(0, exp)}">0</span><small>天</small>`}</span><div class="kpi-foot"><span class="muted small">${exp == null ? '许可证信息由管理员录入' : `至 ${esc(S.licenseExpiry)}${S.licenseNo ? ' · ' + esc(S.licenseNo) : ''}`}</span></div></div>
      </div>
      <div class="grid">
        ${card('检测集群节点', '<div class="nodes" id="nodes"></div>', { cls: 'span-2', sub: '节点通过 /api/v1/ingest/nodes 上报心跳', extra: '<span class="pill pill-live">实时</span>' })}
        ${card('平台服务健康', '<ul class="svc" id="svc"></ul>', { sub: '实时检查' })}
      </div>
      ${card('第三方集成', `<div class="integ" id="integ"></div>`, { sub: '身份源、安全运营、外发通道与通知协同' })}
      <div class="grid g2" style="margin-top:16px">
        ${card('授权许可', `<ul class="lic"><li>${ic('key')}<span>许可编号</span><span class="sp"></span><b>${esc(S.licenseNo || '未配置')}</b></li><li>${ic('monitor')}<span>授权终端数</span><span class="sp"></span><b>${total ? fmt(total) : '未配置'}</b></li><li>${ic('clock')}<span>到期日期</span><span class="sp"></span><b>${esc(S.licenseExpiry || '未配置')}</b></li><li>${ic('users')}<span>已接入终端</span><span class="sp"></span><b>${fmt(used)}</b></li></ul>`, { sub: '在系统设置中维护', extra: UI.can('settings') ? '<a class="link" href="#/settings">编辑</a>' : '' })}
        ${card('版本与规则库', `
          <div class="ver"><div><span>平台版本</span><b id="pv">-</b><small id="pvs"></small></div><div><span>规则库</span><b id="rv">${esc(S.ruleVersion || '-')}</b><small id="rvs">离线规则包升级</small></div><div><span>Agent 最新版</span><b id="av">-</b><small id="avs"></small></div></div>
          <div class="upd" id="upd"><div class="progress"><i></i></div><small class="muted" id="updT"></small></div>
          <div class="ver-act"><button class="btn btn-primary" id="updBtn" data-perm="ops:cfg">${ic('download')}检查规则库更新</button><button class="btn" id="bk" data-perm="ops:cfg">${ic('save')}导出配置快照</button><span class="muted small">业务数据请使用 pg_dump 备份数据库</span></div>`, { sub: '平台与终端版本' })}
      </div>`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      $$('[data-n]', root).forEach(el => countUp(el, +el.dataset.n));
      const hist = { q: [], l: [] };
      function nodesHtml() {
        return D.nodes.map((n, i) => `<div class="node ${n.status}" style="--i:${i}">
          <div class="node-h"><span class="node-ic">${ic(n.role.includes('网关') ? 'globe' : n.role === '管理节点' ? 'settings' : 'cpu')}</span><div><b>${esc(n.name)}</b><small>${esc(n.role)} · ${esc(n.ip)}</small></div><span class="node-st" data-tip="${n.status === 'warning' ? '响应延迟偏高' : '运行正常'}"></span></div>
          <div class="node-m"><span>CPU</span><div class="meter"><i class="${n.cpu > 80 ? 'hot' : n.cpu > 60 ? 'warm' : 'ok'}" style="--w:${n.cpu}%"></i></div><b>${n.cpu}%</b></div>
          <div class="node-m"><span>内存</span><div class="meter"><i class="${n.mem > 80 ? 'hot' : n.mem > 65 ? 'warm' : 'ok'}" style="--w:${n.mem}%"></i></div><b>${n.mem}%</b></div>
          <div class="node-f"><span>${ic('activity', 'ic-in')}<b class="nq">${fmt(n.qps)}</b> 次/秒</span><span class="muted">运行 ${n.up} 天</span></div></div>`).join('');
      }
      const renderNodes = () => { q('#nodes').innerHTML = D.nodes.length ? nodesHtml() : `<div class="empty-st" style="grid-column:1/-1">${ic('server')}<p>尚无检测节点上报心跳</p></div>`; q('#nodeCnt').textContent = `${D.nodes.filter(n => n.status !== 'offline').length} / ${D.nodes.length} 个节点在线`; };
      renderNodes();
      const ENV = { production: ['生产环境', 'pill-ok'], development: ['开发环境', 'pill-live'], demo: ['演示环境', 'pill-live'] };
      const paint = () => {
        if (hist.q.length > 1) { C.spark(q('#spQ'), hist.q, 'c1'); C.spark(q('#spL'), hist.l, 'c2'); }
        $$('#spQ path, #spL path, #spQ circle, #spL circle', root).forEach(p => p.classList.remove('anim-draw', 'anim-fade'));
      };
      API.get('/ops/metrics').then(m => {
        const e = ENV[m.env] || ENV.production;
        q('#envPill2').className = 'pill ' + e[1]; q('#envPill2').textContent = e[0];
        q('#svc').innerHTML = m.health.map((h, k) => `<li style="--i:${k}"><span class="svc-ic">${ic(h.icon)}</span><span>${esc(h.name)}</span><span class="sp"></span><span class="muted small mono">${esc(h.detail)}</span><span class="svc-st ${h.ok ? '' : 'warn'}" data-tip="${h.ok ? '正常' : '异常'}"></span></li>`).join('');
        q('#pv').textContent = 'v' + m.version; q('#pvs').textContent = { production: '生产模式', development: '开发模式', demo: '演示模式' }[m.env] || '';
        q('#av').textContent = m.agentLatest || '-';
        q('#avs').textContent = m.fleet.deployed ? `覆盖率 ${Math.round(m.agentLatestCount / m.fleet.deployed * 100)}%` : '尚无终端接入';
        hist.q = m.qps; hist.l = m.lat;
        if (m.qps.length) { countUp(q('#qps'), m.qps[m.qps.length - 1]); countUp(q('#lat'), m.lat[m.lat.length - 1]); }
        if (hist.q.length > 1) { C.spark(q('#spQ'), hist.q, 'c1'); C.spark(q('#spL'), hist.l, 'c2'); }
      }).catch(UI.apiError);
      // 集群指标由服务端每 2 秒推送
      UI.listen('nodes', m => {
        const changed = m.nodes.length !== D.nodes.length;
        D.nodes = m.nodes;
        if (changed) renderNodes();
        $$('.node', root).forEach((el, i) => {
          const n = D.nodes[i]; if (!n) return;
          const ms = $$('.node-m', el);
          [n.cpu, n.mem].forEach((v, k) => { const bar = ms[k].querySelector('i'); bar.style.animation = 'none'; bar.style.width = v + '%'; bar.className = v > 80 ? 'hot' : v > (k ? 65 : 60) ? 'warm' : 'ok'; ms[k].querySelector('b').textContent = v + '%'; });
          el.querySelector('.nq').textContent = fmt(n.qps);
        });
        q('#qps').textContent = fmt(m.qps); q('#lat').textContent = m.lat;
        hist.q.push(m.qps); hist.l.push(m.lat);
        if (hist.q.length > 20) { hist.q.shift(); hist.l.shift(); }
        paint();
      });

      // 告警通道投递统计
      function delivery(d) {
        if (!d) return '';
        const t = new Date(d.lastAt).toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' });
        return `<small class="ig-dl${d.lastErr ? ' bad' : ''}" title="${esc(d.lastErr || '')}">已投递 ${fmt(d.ok)} · 失败 ${fmt(d.fail)} · 最近 ${t}${d.lastErr ? ' · ' + esc(d.lastErr.slice(0, 40)) : ''}</small>`;
      }
      function renderInteg() {
        let cat = '';
        q('#integ').innerHTML = D.integrations.map((it, i) => {
          const head = it.cat !== cat ? `<div class="integ-cat">${(cat = it.cat)}</div>` : '';
          return head + `<div class="ig ${it.st}" data-k="${it.key}" style="--i:${i}"><span class="ig-ic">${ic(it.icon)}</span><div class="ig-m"><b>${it.name}</b><small>${esc(it.info)}</small>${delivery(it.delivery)}</div>
            <span class="tag ${IST[it.st][1]}">${IST[it.st][0]}</span>
            <div class="ig-a">${it.st === 'off' ? `<button class="btn btn-sm" data-cfg>${ic('link')}立即配置</button>` : `<button class="btn btn-sm btn-ghost" data-test>${ic('refresh')}测试连接</button><button class="btn btn-sm btn-ghost" data-cfg>${ic('settings')}配置</button>`}</div></div>`;
        }).join('');
      }
      q('#integ').addEventListener('click', e => {
        const el = e.target.closest('.ig'); if (!el) return;
        const it = D.integrations.find(x => x.key === el.dataset.k);
        const tb = e.target.closest('[data-test]');
        if (tb) return act(tb, () => API.post(`/integrations/${encodeURIComponent(it.key)}/test`), r => {
          toast(esc(r.message), { type: !r.ok ? 'error' : r.warn ? 'warning' : 'success', title: r.ok ? (r.warn ? '连接偏慢' : '连接测试通过') : '连接测试失败' });
        });
        if (e.target.closest('[data-cfg]')) openCfg(it);
      });
      function openCfg(it) {
        // [字段, 默认值, 可选]；字段名与服务端告警通道配置一致
        const tpl = {
          smtp: [['SMTP 服务器', 'smtp.corp.example:587'], ['加密方式', 'starttls'], ['发件人', 'dlp@corp.example'], ['收件人', ''], ['用户名', '', 1], ['口令', '', 1]],
          wecom: [['Webhook 地址', 'https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=']],
          ding: [['Webhook 地址', 'https://oapi.dingtalk.com/robot/send?access_token='], ['加签密钥', '', 1]],
          siem: [['Syslog 地址', ''], ['端口', '514'], ['协议', 'udp']],
          soar: [['平台地址', 'https://soar.corp.example'], ['API Key', '']],
          casb: [['租户 ID', ''], ['API 端点', 'https://api.casb.example']],
          itsm: [['ITSM 地址', 'https://itsm.corp.example'], ['工单类型', '安全事件']]
        }[it.key] || [['服务地址', ''], ['认证令牌', '']];
        // 已配置的集成使用服务端配置（密钥类字段以 ****** 掩码返回，保存时保持不变）
        const opt = new Set(tpl.filter(f => f[2]).map(f => f[0]));
        const hint = { '加密方式': 'starttls / tls / none', '收件人': '多个邮箱用逗号分隔', '协议': 'udp / tcp' };
        const fields = it.config && Object.keys(it.config).length ? Object.entries(it.config) : tpl.map(f => [f[0], f[1]]);
        // 已有配置缺少模板字段时补齐（例如升级后新增的字段）
        if (it.config) tpl.forEach(([l, v]) => { if (!(l in it.config)) fields.push([l, v]); });
        const { panel, close } = openLayer('modal', `
          <div class="md-head"><div><h2>${it.name}</h2><p>${it.cat} · ${esc(it.info)}</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
          <div class="md-body">${fields.map(([l, v]) => `<div class="field"><label class="lbl">${esc(l)}${opt.has(l) ? ' <small class="muted">（可选）</small>' : ' <em>*</em>'}</label><input class="input" data-f="${esc(l)}" ${opt.has(l) ? 'data-opt' : ''} value="${esc(v)}" ${/key|secret|token|令牌|密码|口令|密钥/i.test(l) ? 'type="password" placeholder="请输入（加密存储）"' : hint[l] ? `placeholder="${hint[l]}"` : ''}></div>`).join('')}
            <label class="set-row"><div><b>启用该集成</b><small>保存后立即生效，可随时停用</small></div><span class="switch"><input type="checkbox" id="igOn" ${it.st !== 'off' || !it.config ? 'checked' : ''}><span></span></span></label></div>
          <div class="md-foot"><button class="btn" data-t>${ic('refresh')}测试连接</button><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok data-perm="ops:cfg">${ic('save')}保存</button></div>`);
        UI.applyPerms(panel);
        panel.querySelector('[data-t]').addEventListener('click', e => act(e.currentTarget, () => API.post(`/integrations/${encodeURIComponent(it.key)}/test`), r => toast(esc(r.message), { type: r.ok ? 'success' : 'error' })));
        panel.querySelector('[data-ok]').addEventListener('click', e => {
          const req = $$('input[data-f]:not([data-opt])', panel);
          const empty = req.filter(i => !i.value.trim());
          req.forEach(i => i.classList.toggle('err', !i.value.trim()));
          if (empty.length) { empty[0].focus(); return; }
          const config = Object.fromEntries($$('input[data-f]', panel).map(i => [i.dataset.f, i.value.trim()]));
          act(e.currentTarget, () => API.put('/integrations/' + encodeURIComponent(it.key), { config, enabled: panel.querySelector('#igOn').checked }), upd => {
            Object.assign(it, upd); close(); renderInteg();
            toast(`${esc(it.name)} 集成${it.st === 'off' ? '已停用' : '已保存并启用'}`, { type: 'success', title: '保存成功' });
          });
        });
      }
      renderInteg();

      q('#diag').addEventListener('click', e => act(e.currentTarget, () => API.post('/ops/diagnose'), r => toast(r.issues.length ? `发现 ${r.issues.length} 项需关注：${r.issues.map(esc).join('；')}` : '未发现异常', { type: r.issues.length ? 'warning' : 'success', title: '诊断报告', dur: 6000 })));
      q('#bk').addEventListener('click', e => act(e.currentTarget, () => API.post('/ops/backup'), r => toast(`配置快照已保存至服务端 data/backups/${esc(r.file)}（${esc(r.size)}）`, { type: 'success', title: '导出成功' })));
      q('#updBtn').addEventListener('click', async e => {
        const b = e.currentTarget, box = q('#upd'), bar = box.querySelector('i'), txt = q('#updT');
        const r = await act(b, () => API.post('/ops/rules-update'));
        if (!r) return;
        if (r.upToDate) { toast(`规则库已是最新版本 ${esc(r.version)}`, { type: 'info' }); return; }
        b.disabled = true; box.classList.add('show');
        const steps = [[0, '下载规则包…'], [30, '校验 SM2 数字签名…'], [55, '灰度下发至 dlp-engine-01…'], [80, '全量下发至检测节点…'], [100, '更新完成']];
        const iv2 = setInterval(async () => {
          let j;
          try { j = await API.get('/jobs/' + r.job.id); } catch (err) { clearInterval(iv2); b.disabled = false; return; }
          bar.style.width = j.progress + '%';
          txt.textContent = steps.filter(s2 => j.progress >= s2[0]).pop()[1];
          if (j.status !== 'run') {
            clearInterval(iv2); b.disabled = false;
            if (j.status === 'done') {
              D.settings.ruleVersion = r.version;
              q('#rv').textContent = r.version; q('#rvs').textContent = '已是最新版本';
              toast(`规则库已更新至 ${esc(r.version)}，已下发至全部检测节点`, { type: 'success', title: '更新完成' });
            }
            setTimeout(() => box.classList.remove('show'), 1200);
          }
        }, 500);
        UI.onCleanup(() => clearInterval(iv2));
      });
    }
  };
})();
