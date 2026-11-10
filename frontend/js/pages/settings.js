/* 系统设置 */
(function () {
  'use strict';
  const { D, ic, $$, esc, toast, card, act } = UI;
  const val = (k, d) => (D.settings && D.settings[k] !== undefined ? D.settings[k] : d);

  const sw = (key, title, desc, on) => `<label class="set-row"><div><b>${title}</b><small>${desc}</small></div><span class="switch"><input type="checkbox" data-k="${key}" ${val(key, on) ? 'checked' : ''}><span></span></span></label>`;
  const sel = (key, title, desc, opts, v) => `<div class="set-row"><div><b>${title}</b><small>${desc}</small></div><select class="input" data-k="${key}">${opts.map(o => `<option ${o === val(key, v) ? 'selected' : ''}>${o}</option>`).join('')}</select></div>`;

  // 告警通道说明取自「运维中心 → 第三方集成」中的真实配置
  const integ = k => (D.integrations || []).find(i => i.key === k);
  const chDesc = (k, fn) => { const it = integ(k); return it && it.st !== 'off' && it.config ? fn(it.config) : '未配置，请在「运维中心 → 第三方集成」中设置'; };

  UI.pages.settings = {
    title: '系统设置', icon: 'settings',
    html() {
      return `
      <div class="page-head"><div><h1>系统设置</h1><p>告警通知、授权许可、AI 分析、账号安全与数据保留</p></div></div>
      <div class="grid g2">
        ${card('告警通知', `
          ${sw('mail', '邮件通知', esc(chDesc('smtp', c => '发送至 ' + (c['收件人'] || '—'))), false)}
          ${sw('wecom', '企业微信', esc(chDesc('wecom', () => '群机器人已配置')), false)}
          ${sw('ding', '钉钉', esc(chDesc('ding', c => '群机器人已配置' + (c['加签密钥'] ? '（加签）' : ''))), false)}
          ${sw('siem', 'SIEM / Syslog 转发', esc(chDesc('siem', c => `转发至 ${c['Syslog 地址']}${String(c['Syslog 地址']).includes(':') ? '' : ':' + (c['端口'] || 514)}（${(c['协议'] || 'udp').toUpperCase()}，CEF 格式）`)), false)}
          <div class="set-row"><div><b>控制台访问地址</b><small>告警消息中「查看详情」链接的前缀</small></div><input class="input" data-k="consoleUrl" value="${esc(val('consoleUrl', ''))}" placeholder="https://dlp.corp.example" maxlength="200"></div>
          ${sel('freq', '告警汇总频率', '中低危事件合并推送的时间间隔', ['实时', '每 15 分钟', '每小时', '每日汇总'], '每 15 分钟')}`, { sub: '事件告警推送渠道' })}
        ${card('授权许可', `
          <div class="set-row"><div><b>许可编号</b><small>由软件供应商提供</small></div><input class="input" data-k="licenseNo" value="${esc(val('licenseNo', ''))}" maxlength="40"></div>
          <div class="set-row"><div><b>授权终端数</b><small>用于终端授权用量统计</small></div><input class="input" type="number" min="0" data-k="licenseSeats" value="${val('licenseSeats', 0)}"></div>
          <div class="set-row"><div><b>到期日期</b><small>到期前 30 天在运维页提醒</small></div><input class="input" type="date" data-k="licenseExpiry" value="${esc(val('licenseExpiry', ''))}"></div>`, { sub: '许可证信息' })}
        ${card('AI 分析', `
          ${sw('aiRedact', '发送前脱敏', '姓名、终端、IP、邮箱替换为代号，身份证号与手机号遮盖，结果在本地还原；任何情况下不发送文件内容', true)}
          ${sw('aiReport', '报表 AI 管理摘要', '生成报表（含定时报表）时由 AI 撰写管理摘要', true)}
          <p class="muted small" style="margin-top:10px">${esc(chDesc('ai', c => '当前模型：' + (c['模型'] || '-') + ' · ' + (c['接口地址'] || '')))}</p>`, { sub: '大模型接入与数据保护' })}
        ${card('账号安全', `
          <div class="set-row"><div><b>管理员口令有效期</b><small>到期后登录须先修改口令；初始口令与重置后的口令首次登录必须修改</small></div><select class="input" data-k="pwdMaxAge" data-num>${[[30, '30 天'], [60, '60 天'], [90, '90 天'], [180, '180 天'], [365, '365 天'], [0, '不过期']].map(([v, t]) => `<option value="${v}" ${+val('pwdMaxAge', 90) === v ? 'selected' : ''}>${t}</option>`).join('')}</select></div>`, { sub: '身份鉴别（等保 2.0）' })}
        ${card('数据保留', `
          ${sel('ret1', '事件记录保留', '超期的已关闭事件每日自动删除；审计日志不会被删除', ['90 天', '180 天', '365 天', '永久'], '365 天')}`, { sub: '历史数据清理' })}
      </div>
      <div class="savebar" id="savebar">${ic('alert')}<span>有未保存的更改</span><span class="sp"></span><button class="btn" id="discard">放弃</button><button class="btn btn-primary" id="save" data-perm="settings:cfg">${ic('save')}保存设置</button></div>`;
    },
    mount(root) {
      const bar = root.querySelector('#savebar');
      const dirty = () => bar.classList.add('show');
      root.addEventListener('change', e => { if (e.target.dataset.k) dirty(); });
      root.addEventListener('input', e => { if (e.target.dataset.k && e.target.tagName === 'INPUT' && e.target.type !== 'checkbox') dirty(); });
      root.querySelector('#discard').addEventListener('click', () => { UI.rerender(); toast('已放弃未保存的更改', { type: 'info' }); });
      root.querySelector('#save').addEventListener('click', e => {
        const body = {};
        $$('[data-k]', root).forEach(el => { body[el.dataset.k] = el.type === 'checkbox' ? el.checked : el.type === 'range' || el.type === 'number' || el.hasAttribute('data-num') ? +el.value : el.value; });
        act(e.currentTarget, () => API.put('/settings', body), r => {
          D.settings = r.settings; bar.classList.remove('show');
          toast(r.changed.length ? `已更新 ${r.changed.length} 项配置` : '配置未发生变化', { type: 'success', title: '保存成功' });
        });
      });
    }
  };
})();
