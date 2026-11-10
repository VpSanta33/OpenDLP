/* 策略管理 + 新建策略向导 */
(function () {
  'use strict';
  const { D, ic, $$, fmt, esc, relTime, toast, seg, initSeg, openLayer, act, SEV, ACT } = UI;
  const POL_ACT = { block: '阻断外发', encrypt: '加密放行', audit: '仅审计' };

  function polCard(p, i, isNew) {
    return `<article class="pol-card ${p.enabled ? '' : 'off'} ${isNew ? 'new' : ''}" data-id="${p.id}" style="--i:${i}">
      <div class="pol-head">
        <span class="pol-ic s-${p.severity}">${ic('shield')}</span>
        <div class="pol-title"><h4>${esc(p.name)}</h4><span>${p.id} · ${esc(p.owner)} 更新于 ${relTime(p.updated)}</span></div>
        <label class="switch" title="${p.enabled ? '停用' : '启用'}策略"><input type="checkbox" data-tg ${p.enabled ? 'checked' : ''} ${UI.canDo('policies', 'cfg') ? '' : 'disabled'} aria-label="启用 ${esc(p.name)}"><span></span></label>
      </div>
      <p>${esc(p.desc)}</p>
      <div class="pol-tags">${p.dataTypes.map(k => `<span class="tag">${D.dtMap[k].name}</span>`).join('')}<span class="sev sev-${p.severity}"><i></i>${SEV[p.severity].name}</span></div>
      <div class="pol-foot">
        <div class="pol-chs">${p.channels.map(k => `<span data-tip="${D.chMap[k].name}">${ic(D.chMap[k].icon)}</span>`).join('')}</div>
        <span class="tag ${ACT[p.action].cls}">${ic(ACT[p.action].icon)}${POL_ACT[p.action]}</span>
        <span class="pol-hits"><b data-hits>${fmt(p.hits)}</b>次命中</span>
      </div>
    </article>`;
  }

  /* ---------- 新建策略向导 ---------- */
  function openWizard(onDone) {
    const st = { step: 0, sev: 'high', types: new Set(['idcard']), chs: new Set(['email', 'im']), th: 10, action: 'block', };
    const html = `
      <div class="md-head"><div><h2>新建防泄漏策略</h2><p>3 步完成策略配置，终端 Agent 在下次心跳（约 1 分钟）时同步</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
      <div class="steps">${['基本信息', '检测规则', '响应动作'].map((s, i) => `${i ? '<div class="step-line"><i></i></div>' : ''}<div class="step" data-st="${i}"><b><span>${i + 1}</span>${ic('check')}</b>${s}</div>`).join('')}</div>
      <div class="md-body">
        <div class="step-pane" data-p="0">
          <div class="field"><label class="lbl" for="wName">策略名称 <em>*</em></label><input class="input" id="wName" maxlength="40" placeholder="例如：研发中心源代码外发拦截"><div class="field-err" id="wNameErr">请填写策略名称</div></div>
          <div class="field"><label class="lbl" for="wDesc">策略描述</label><textarea class="input" id="wDesc" placeholder="简要说明策略的检测目标与适用范围"></textarea></div>
          <div class="field"><div class="lbl">严重级别</div><div class="opt-grid c4" data-g="sev">${Object.keys(SEV).map(s => `<div class="opt ${s === st.sev ? 'on' : ''}" data-v="${s}"><span class="sev-dot sev-dot-${s}"></span>${SEV[s].name}</div>`).join('')}</div></div>
        </div>
        <div class="step-pane" data-p="1">
          <div class="field"><div class="lbl">敏感数据类型 <span class="hint">可多选</span></div><div class="chips" data-g="types">${D.dataTypes.map(d => `<span class="chip ${st.types.has(d.key) ? 'on' : ''}" data-v="${d.key}">${ic('check')}${d.name}</span>`).join('')}</div></div>
          <div class="field"><div class="lbl">监控通道 <span class="hint">可多选</span></div><div class="opt-grid" data-g="chs">${D.channels.map(c => `<div class="opt ${st.chs.has(c.key) ? 'on' : ''}" data-v="${c.key}">${ic(c.icon)}${c.name}</div>`).join('')}</div></div>
          <div class="field"><div class="lbl">匹配阈值 <span class="hint">单次外发命中 ≥ <b id="thV">10</b> 处时触发</span></div><input type="range" class="range" id="wTh" min="1" max="100" value="10" aria-label="匹配阈值"></div>
        </div>
        <div class="step-pane" data-p="2">
          <div class="field"><div class="lbl">响应动作</div><div class="act-grid" data-g="action">${[['block', '阻断 / 隔离', '终端 Agent 将文件移入隔离区并留下说明；网关按自身能力阻断', 'ban'], ['encrypt', '加密放行', '需由支持加密的网关执行；终端 Agent 按审计记录', 'lock'], ['audit', '仅审计', '允许外发，生成事件记录', 'eye']].map(([v, t, d, icn]) => `<div class="act-opt ${v === st.action ? 'on' : ''}" data-v="${v}"><div class="act-ic">${ic(icn)}</div><b>${t}</b><p>${d}</p></div>`).join('')}</div></div>
          <div class="summary" id="wSum"></div>
        </div>
      </div>
      <div class="md-foot"><span class="muted small" id="wStep">第 1 / 3 步</span><span class="sp"></span><button class="btn" id="wPrev">${ic('chevron-left')}上一步</button><button class="btn btn-primary" id="wNext">下一步${ic('arrow-right')}</button></div>`;
    const { panel, close } = openLayer('modal', html);
    const q = s => panel.querySelector(s);
    const nameIn = q('#wName'), prev = q('#wPrev'), next = q('#wNext');

    const shake = el => { el.classList.remove('shake'); void el.offsetWidth; el.classList.add('shake'); };
    function summary() {
      const name = esc(nameIn.value.trim());
      q('#wSum').innerHTML = `<div class="summary-t">${ic('shield-check')}策略预览</div>
        当 <b>${[...st.chs].map(k => D.chMap[k].name).join('、')}</b> 中检测到 <b>${[...st.types].map(k => D.dtMap[k].name).join('、')}</b> 命中 ≥ <b>${st.th}</b> 处时，
        执行 <b>${{ block: '阻断外发', encrypt: '加密放行', audit: '仅审计' }[st.action]}</b>，事件级别为 <b>${SEV[st.sev].name}</b>。<br>策略名称：<b>${name}</b>`;
    }
    function go(n) {
      const back = n < st.step; st.step = n;
      $$('.step', panel).forEach((s, i) => { s.classList.toggle('on', i === n); s.classList.toggle('done', i < n); });
      $$('.step-line', panel).forEach((l, i) => l.classList.toggle('done', i < n));
      $$('.step-pane', panel).forEach((p, i) => { p.classList.toggle('back', back); p.classList.toggle('on', i === n); });
      prev.style.visibility = n ? 'visible' : 'hidden';
      next.innerHTML = n === 2 ? `${ic('send')}发布策略` : `下一步${ic('arrow-right')}`;
      q('#wStep').textContent = `第 ${n + 1} / 3 步`;
      if (n === 2) summary();
      if (n === 0) setTimeout(() => nameIn.focus(), 80);
    }
    function validate() {
      if (st.step === 0 && !nameIn.value.trim()) {
        nameIn.classList.add('err'); shake(nameIn); q('#wNameErr').classList.add('show'); nameIn.focus(); return false;
      }
      if (st.step === 1 && (!st.types.size || !st.chs.size)) {
        shake(q(!st.types.size ? '[data-g="types"]' : '[data-g="chs"]'));
        toast('请至少选择一种数据类型和一个监控通道', { type: 'warning' });
        return false;
      }
      return true;
    }
    nameIn.addEventListener('input', () => { nameIn.classList.remove('err'); q('#wNameErr').classList.remove('show'); });
    q('#wTh').addEventListener('input', e => { st.th = +e.target.value; q('#thV').textContent = st.th; });
    panel.addEventListener('click', e => {
      const o = e.target.closest('[data-g] [data-v]'); if (!o) return;
      const g = o.closest('[data-g]').dataset.g, v = o.dataset.v;
      if (g === 'sev' || g === 'action') {
        st[g] = v; $$('[data-v]', o.parentNode).forEach(x => x.classList.toggle('on', x === o));
      } else {
        st[g].has(v) ? st[g].delete(v) : st[g].add(v); o.classList.toggle('on', st[g].has(v));
      }
    });
    prev.addEventListener('click', () => go(Math.max(0, st.step - 1)));
    next.addEventListener('click', () => {
      if (!validate()) return;
      if (st.step < 2) { go(st.step + 1); return; }
      const body = { name: nameIn.value.trim(), desc: q('#wDesc').value.trim(), channels: [...st.chs], dataTypes: [...st.types], action: st.action, severity: st.sev, threshold: st.th };
      act(next, () => API.post('/policies', body), p => {
        close(); onDone(p);
        toast(`策略「${esc(p.name)}」已发布，终端 Agent 将在下次心跳时同步`, { type: 'success', title: '发布成功' });
      });
    });
    panel.addEventListener('keydown', e => { if (e.key === 'Enter' && e.target.tagName === 'INPUT' && e.target.type === 'text') { e.preventDefault(); next.click(); } });
    go(0);
  }

  UI.pages.policies = {
    title: '策略管理', icon: 'shield',
    html() {
      return `
      <div class="page-head">
        <div><h1>策略管理</h1><p>按外发渠道与数据类型配置响应动作，终端 Agent 在心跳时同步策略变更</p></div>
        <div class="head-actions"><button class="btn" data-act="tpl" data-perm="policies:cfg">${ic('copy')}合规模板</button><button class="btn btn-primary" data-act="new" data-perm="policies:cfg">${ic('plus')}新建策略</button></div>
      </div>
      <div class="toolbar">
        ${seg('pf', [['all', '全部'], ['on', '已启用'], ['off', '已停用']], 'all')}
        <div class="search-box">${ic('search')}<input class="input" id="pq" placeholder="搜索策略名称或描述…"></div>
        <span class="sp"></span><span class="muted" id="polStat"></span>
      </div>
      <div class="pol-grid" id="polGrid"></div>`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      const grid = q('#polGrid');
      let filt = 'all', kw = '', newId = null;
      const stat = () => { q('#polStat').textContent = `已启用 ${D.policies.filter(p => p.enabled).length} / ${D.policies.length} 条策略`; };
      function render() {
        const L = D.policies.filter(p => (filt === 'all' || (filt === 'on' ? p.enabled : !p.enabled)) && (!kw || (p.name + p.desc).includes(kw)));
        grid.innerHTML = L.length ? L.map((p, i) => polCard(p, i, p.id === newId)).join('')
          : `<div class="empty-st" style="grid-column:1/-1">${ic('shield')}<p>${D.policies.length ? '没有符合条件的策略' : '尚未配置策略。可点击「合规模板」导入内置模板，或新建策略'}</p></div>`;
        newId = null; stat();
      }
      grid.addEventListener('change', e => {
        if (!e.target.matches('[data-tg]')) return;
        const cardEl = e.target.closest('.pol-card'), p = D.policies.find(x => x.id === cardEl.dataset.id), sw = e.target, want = sw.checked;
        sw.disabled = true;
        API.patch('/policies/' + encodeURIComponent(p.id), { enabled: want }).then(upd => {
          Object.assign(p, upd);
          cardEl.classList.toggle('off', !p.enabled);
          stat();
          toast(`策略「${esc(p.name)}」已${p.enabled ? '启用，终端 Agent 将在下次心跳时同步' : '停用'}`, { type: p.enabled ? 'success' : 'warning' });
          if (filt !== 'all') setTimeout(render, 450);
        }).catch(err => { sw.checked = !want; UI.apiError(err); }).finally(() => { sw.disabled = !UI.canDo('policies', 'cfg'); });
      });
      initSeg(root, 'pf', v => { filt = v; render(); });
      let t; q('#pq').addEventListener('input', e => { clearTimeout(t); t = setTimeout(() => { kw = e.target.value.trim(); render(); }, 160); });
      const openNew = () => openWizard(p => { D.policies.unshift(p); newId = p.id; render(); });
      q('[data-act="new"]').addEventListener('click', openNew);
      q('[data-act="tpl"]').addEventListener('click', e => act(e.currentTarget, () => API.post('/policies/templates/sync'), r => {
        D.policies = r.policies; render();
        toast(r.added ? `已导入 ${r.added} 条内置合规策略模板（停用状态），确认后可逐条启用` : '内置合规模板均已导入', { type: 'info', title: '合规模板' });
      }));
      render();
      if (UI.params.get('new') && UI.canDo('policies', 'cfg')) setTimeout(openNew, 250);
    }
  };
})();
