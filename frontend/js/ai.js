/* AI 分析：事件 AI 研判面板、AI 安全助手 */
(function () {
  'use strict';
  const { ic, esc, toast, act, fmtTime, openLayer } = UI;

  /* ---------- 轻量 Markdown 渲染（先转义，再处理少量语法） ---------- */
  function inline(s) {
    return esc(s)
      .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
      .replace(/`([^`]+)`/g, '<code>$1</code>');
  }
  function md(src) {
    const lines = String(src || '').replace(/\r/g, '').split('\n');
    let html = '', list = null, table = null;
    const flush = () => {
      if (list) { html += `<${list.t}>${list.items.map(x => `<li>${inline(x)}</li>`).join('')}</${list.t}>`; list = null; }
      if (table) {
        const [head, ...rows] = table.filter(r => !/^\s*\|?\s*:?-{2,}/.test(r.join('|')));
        html += `<div class="table-wrap"><table class="table compact-t"><thead><tr>${head.map(c => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${inline(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
        table = null;
      }
    };
    for (const raw of lines) {
      const l = raw.trim();
      let m;
      if (/^\|.*\|$/.test(l)) { if (list) flush(); (table = table || []).push(l.slice(1, -1).split('|').map(c => c.trim())); continue; }
      if (table) flush();
      if ((m = l.match(/^[-*•]\s+(.*)/)) || (m = l.match(/^\d+[.、)]\s*(.*)/))) {
        const t = /^\d/.test(l) ? 'ol' : 'ul';
        if (list && list.t !== t) flush();
        (list = list || { t, items: [] }).items.push(m[1]);
        continue;
      }
      flush();
      if (!l) continue;
      if ((m = l.match(/^#{1,4}\s+(.*)/))) html += `<h5>${inline(m[1])}</h5>`;
      else html += `<p>${inline(l)}</p>`;
    }
    flush();
    return html;
  }

  /* ---------- 事件 AI 研判 ---------- */
  const RISK = { high: ['高风险', 'b-danger'], medium: ['中风险', 'b-warning'], low: ['低风险', 'b-success'] };
  const DISP = { escalate: '建议升级调查', monitor: '建议持续观察', resolve: '建议核实后关闭', fp: '建议标记为误报' };
  const CONF = { high: '高', medium: '中', low: '低' };

  function triageHtml(t) {
    const r = RISK[t.risk] || RISK.medium;
    return `<div class="ai-res">
      <div class="ai-top"><span class="tag ${r[1]}">${r[0]} · ${t.score}</span><b>${esc(DISP[t.disposition] || '')}</b><span class="muted small">置信度 ${CONF[t.confidence] || '中'}</span></div>
      <p class="ai-sum">${esc(t.summary)}</p>
      ${t.reasons.length ? `<h5>判断依据</h5><ul>${t.reasons.map(x => `<li>${esc(x)}</li>`).join('')}</ul>` : ''}
      ${t.recommendations.length ? `<h5>处置建议</h5><ol>${t.recommendations.map(x => `<li>${esc(x)}</li>`).join('')}</ol>` : ''}
      <div class="ai-meta">${ic('wand')}${esc(t.model)} · ${esc(t.by)} · ${fmtTime(t.ts)}${t.redacted ? ' · 已脱敏发送' : ''}<span class="sp"></span>
        <button class="link-btn" data-ai-run data-perm="incidents:op">${ic('refresh')}重新研判</button></div>
      <p class="muted small">AI 结论仅供参考，请结合实际情况人工确认后处置。</p></div>`;
  }

  // 在事件抽屉中挂载 AI 研判区块
  async function mountTriage(box, inc) {
    const empty = () => {
      box.innerHTML = `<div class="ai-empty">${ic('wand')}<div><b>让 AI 结合该用户近 90 天的行为、员工状态与审批记录研判风险</b><small>默认对姓名、终端、IP 等脱敏后发送，不发送文件内容</small></div>
        <button class="btn btn-sm btn-primary" data-ai-run data-perm="incidents:op">${ic('wand')}AI 研判</button></div>`;
      UI.applyPerms(box);
    };
    box.addEventListener('click', e => {
      const b = e.target.closest('[data-ai-run]'); if (!b || b.disabled) return;
      box.classList.add('ai-busy');
      act(b, () => API.post(`/ai/incidents/${encodeURIComponent(inc.id)}/triage`), t => { box.innerHTML = triageHtml(t); UI.applyPerms(box); })
        .finally(() => box.classList.remove('ai-busy'));
    });
    try {
      const t = await API.get(`/ai/incidents/${encodeURIComponent(inc.id)}`);
      if (t && t.summary) { box.innerHTML = triageHtml(t); UI.applyPerms(box); } else empty();
    } catch (e) { empty(); }
  }

  /* ---------- AI 安全助手 ---------- */
  const SUGGEST = ['近 7 天哪些部门的高危事件最多？', '本月 U 盘外发的身份证号事件有哪些？', '分析一下事件最多的员工的风险', '哪些终端离线了？', '当前启用的阻断策略覆盖了哪些渠道？'];
  const TOOL = { incident_stats: '统计事件', search_incidents: '查询事件', user_profile: '查看员工画像', list_policies: '读取策略', endpoint_overview: '读取终端状态' };
  let history = []; // 本次登录内保留对话

  function bubble(m) {
    if (m.role === 'user') return `<div class="ai-msg me"><div>${esc(m.content)}</div></div>`;
    const tools = (m.tools || []).map(t => `<span class="tag" title="${esc(JSON.stringify(t.args))}">${ic(t.ok ? 'check' : 'x')}${TOOL[t.name] || esc(t.name)}</span>`).join('');
    return `<div class="ai-msg bot ${m.error ? 'err' : ''}"><span class="ai-av">${ic('wand')}</span><div>${tools ? `<div class="ai-tools">${tools}</div>` : ''}${m.error ? esc(m.content) : md(m.content)}
      ${m.model ? `<small class="muted">${esc(m.model)}${m.redacted ? ' · 已脱敏' : ''}</small>` : ''}</div></div>`;
  }

  function openAssistant() {
    const { panel } = openLayer('drawer ai-drawer', `
      <div class="dr-head"><div class="dr-meta"><span class="tag b-primary">${ic('wand')}AI</span><span class="muted small">只读查询 · 按当前角色权限</span></div>
        <h2>AI 安全助手</h2><p>用自然语言查询事件、员工风险、策略与终端状态</p>
        <button class="icon-btn dr-close" data-close aria-label="关闭">${ic('x')}</button></div>
      <div class="dr-body ai-log" id="aiLog"></div>
      <form class="ai-input" id="aiForm"><textarea class="input" id="aiQ" rows="2" maxlength="2000" placeholder="例如：近 30 天离职流程中的员工有哪些外发行为？（Enter 发送，Shift+Enter 换行）"></textarea>
        <div class="ai-act"><button type="button" class="link-btn small" id="aiClear">清空对话</button><span class="sp"></span><button class="btn btn-primary btn-sm" type="submit" id="aiSend">${ic('send')}发送</button></div></form>`);
    const log = panel.querySelector('#aiLog'), q = panel.querySelector('#aiQ'), send = panel.querySelector('#aiSend');
    const render = (pending) => {
      log.innerHTML = history.length ? history.map(bubble).join('') + (pending ? `<div class="ai-msg bot"><span class="ai-av">${ic('wand')}</span><div class="ai-typing"><i></i><i></i><i></i><small class="muted">正在查询与分析…</small></div></div>` : '')
        : `<div class="ai-hello">${ic('wand')}<b>可以问我这些问题</b>${SUGGEST.map(s => `<button type="button" class="chip" data-s="${esc(s)}">${esc(s)}</button>`).join('')}
           <p class="muted small">回答基于平台中的真实数据。默认对姓名、终端、IP 等脱敏后再发送给模型，结果在本地还原；所有提问记入审计日志。</p></div>`;
      log.scrollTop = log.scrollHeight;
    };
    async function ask(text) {
      text = text.trim();
      if (!text || send.disabled) return;
      history.push({ role: 'user', content: text });
      q.value = ''; send.disabled = true; render(true);
      const msgs = history.filter(m => !m.error).slice(-20).map(m => ({ role: m.role, content: m.content }));
      try {
        const r = await API.post('/ai/chat', { messages: msgs });
        history.push({ role: 'assistant', content: r.reply || '（模型没有返回内容）', tools: r.tools, model: r.model, redacted: r.redacted });
      } catch (e) {
        history.push({ role: 'assistant', content: e.message, error: true });
      }
      send.disabled = false; render(false); q.focus();
    }
    panel.querySelector('#aiForm').addEventListener('submit', e => { e.preventDefault(); ask(q.value); });
    q.addEventListener('keydown', e => { if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); ask(q.value); } });
    log.addEventListener('click', e => { const c = e.target.closest('[data-s]'); if (c) ask(c.dataset.s); });
    panel.querySelector('#aiClear').addEventListener('click', () => { history = []; render(false); });
    render(false);
    setTimeout(() => q.focus(), 300);
  }

  UI.ai = { mountTriage, openAssistant, md, reset: () => { history = []; } };
  const btn = document.getElementById('aiBtn');
  if (btn) btn.addEventListener('click', () => { if (UI.me) openAssistant(); });
})();
