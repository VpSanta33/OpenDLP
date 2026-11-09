/* 识别规则库：数据标识符管理 + 实时测试沙箱 */
(function () {
  'use strict';
  const { D, ic, $$, fmt, esc, relTime, countUp, toast, card, openLayer, act, seg, initSeg } = UI;

  const CAT = { pii: ['个人信息', 'b-primary', 'c1'], fin: ['金融数据', 'b-warning', 'c3'], cred: ['凭证密钥', 'b-danger', 'c5'], corp: ['企业机密', 'b-purple', 'c4'] };
  const TYPE = { regex: ['正则表达式', 'code'], keyword: ['关键词词典', 'hash'], edm: ['精确数据匹配 EDM', 'database'], idm: ['文档指纹 IDM', 'fingerprint'], ml: ['机器学习', 'cpu'], file: ['文件类型', 'file'] };

  /* 校验算法 */
  const ID_W = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2], ID_C = '10X98765432';
  const idCheck = s17 => ID_C[s17.split('').reduce((t, c, i) => t + c * ID_W[i], 0) % 11];
  const idOk = s => s.length === 18 && idCheck(s.slice(0, 17)) === s[17].toUpperCase();
  function luhnSum(s) { let sum = 0, alt = false; for (let i = s.length - 1; i >= 0; i--) { let n = +s[i]; if (alt) { n *= 2; if (n > 9) n -= 9; } sum += n; alt = !alt; } return sum; }
  const luhnOk = s => luhnSum(s) % 10 === 0;
  const luhnDigit = s => (10 - luhnSum(s + '0') % 10) % 10;
  const CHECK = { idcard: [idOk, 'GB 11643 校验位'], luhn: [luhnOk, 'Luhn 校验'] };
  const mask = v => v.length <= 6 ? v[0] + '*'.repeat(v.length - 1) : v.slice(0, 3) + '*'.repeat(Math.min(8, v.length - 7)) + v.slice(-4);

  const id17 = '11010519900307231', card18 = '622202020011234884';
  const SAMPLE = `【客户资料 · 内部资料，未经授权不得外传】
客户：陈晓东，身份证号 ${id17 + idCheck(id17)}，手机 13912340912
备用证件：${id17}${idCheck(id17) === '0' ? '1' : '0'}（录入错误）
收款账户：${card18 + luhnDigit(card18)}（工商银行），邮箱 chenxd@example.com
服务器 10.12.3.45 · mysql://app:Passw0rd@10.12.3.45:3306/crm
AWS Key: AKIAIOSFODNN7EXAMPLE
2026Q3 营业收入 3.2 亿元，净利润 4,812 万元。`;

  function findMatches(text, rules) {
    const out = [];
    rules.forEach(r => {
      if (r.type === 'regex') {
        let re; try { re = new RegExp(r.cfg.src, 'g'); } catch (e) { return; }
        for (const m of text.matchAll(re)) {
          if (!m[0]) continue;
          const chk = r.cfg.check && CHECK[r.cfg.check];
          out.push({ s: m.index, e: m.index + m[0].length, v: m[0], r, ok: chk ? chk[0](m[0]) : true });
        }
      } else if (r.type === 'keyword') {
        r.cfg.words.forEach(w => { let i = -1; while ((i = text.indexOf(w, i + 1)) !== -1) out.push({ s: i, e: i + w.length, v: w, r, ok: true }); });
      }
    });
    out.sort((a, b) => a.s - b.s || (b.e - b.s) - (a.e - a.s));
    const res = []; let end = -1;
    out.forEach(m => { if (m.s >= end) { res.push(m); end = m.e; } });
    return res;
  }
  function highlight(text, ms) {
    let h = '', p = 0;
    ms.forEach((m, i) => {
      h += esc(text.slice(p, m.s));
      h += `<mark class="hl ${m.ok ? '' : 'bad'}" style="--c:var(--${CAT[m.r.cat][2]});--i:${i}" title="${esc(m.r.name)}${m.ok ? '' : ' · 校验失败'}">${esc(m.v)}</mark>`;
      p = m.e;
    });
    return h + esc(text.slice(p));
  }

  function cfgHtml(r) {
    const c = r.cfg;
    switch (r.type) {
      case 'regex': return `<div class="code-blk"><span class="muted">/</span>${esc(c.src)}<span class="muted">/g</span><button class="icon-btn sm" data-copy title="复制">${ic('copy')}</button></div>
        <div class="rule-meta">${c.check ? `<span class="tag b-success">${ic('shield-check')}${CHECK[c.check][1]}</span>` : ''}<span class="tag">${ic('activity')}最小命中数 1</span><span class="tag">${ic('layers')}上下文窗口 ±50 字符</span></div>`;
      case 'keyword': return `<div class="chips">${c.words.map(w => `<span class="chip on">${ic('check')}${esc(w)}</span>`).join('')}</div>
        <div class="rule-meta"><span class="tag">匹配方式：全词匹配，忽略大小写</span><span class="tag">邻近度：同段落内命中 ≥ 2 个提升置信度</span></div>`;
      case 'edm': return `<div class="mstat"><div><span>索引记录</span><b>${fmt(c.records)}</b></div><div><span>匹配列</span><b>${c.cols.length}</b></div><div><span>存储方式</span><b>SHA-256 加盐哈希</b></div></div>
        <div class="chips" style="margin-top:12px">${c.cols.map(x => `<span class="chip on">${ic('check')}${x}</span>`).join('')}</div>
        <div class="rule-meta">${c.from ? `<span class="tag">${ic('refresh')}${esc(c.from)}</span>` : ''}<button class="btn btn-sm" data-sync>${ic('refresh')}立即同步</button></div>`;
      case 'idm': return `<div class="mstat"><div><span>指纹文档</span><b>${fmt(c.docs)}</b></div><div><span>相似度阈值</span><b id="simV">${c.sim}%</b></div><div><span>识别能力</span><b>片段 / 改写 / 转格式</b></div></div>
        <input type="range" class="range" min="40" max="100" value="${c.sim}" id="sim" style="margin-top:14px" aria-label="相似度阈值">
        <div class="rule-meta"><button class="btn btn-sm" data-up>${ic('upload')}上传样本文档</button><span class="muted small">支持 Office / PDF / 源代码 / CAD，单次最多 500 个</span></div>`;
      case 'ml': return `<div class="mstat"><div><span>模型准确率</span><b>${c.acc}%</b></div><div><span>训练样本</span><b>${fmt(c.samples)}</b></div><div><span>模型版本</span><b>v2026.10</b></div></div>
        <div class="acc"><span>准确率</span><div class="meter"><i class="ok" style="--w:${c.acc}%"></i></div><span>召回率</span><div class="meter"><i style="--w:${(c.acc - 3.1).toFixed(1)}%"></i></div></div>
        <div class="rule-meta"><button class="btn btn-sm" data-train>${ic('refresh')}使用误报样本再训练</button></div>`;
      default: return `<div class="chips">${c.exts.map(x => `<span class="chip on">${ic('check')}${x}</span>`).join('')}</div>
        <div class="rule-meta"><span class="tag">${ic('shield-check')}基于文件头魔数识别，防止修改扩展名绕过</span></div>`;
    }
  }

  UI.pages.rules = {
    title: '识别规则库', icon: 'fingerprint',
    html() {
      const en = D.rules.filter(r => r.enabled).length, hits = D.rules.reduce((s, r) => s + r.hits, 0);
      return `
      <div class="page-head">
        <div><h1>识别规则库</h1><p>管理敏感数据标识符：正则、关键词词典、精确数据匹配、文档指纹、机器学习与文件类型</p></div>
        <div class="head-actions"><button class="btn btn-primary" id="newRule" data-perm="rules:cfg">${ic('plus')}新建规则</button></div>
      </div>
      <div class="mini-stats">
        <div class="mini"><span class="mini-ic mi-primary">${ic('fingerprint')}</span><div><span>识别规则</span><b data-n="${D.rules.length}">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-success">${ic('check')}</span><div><span>已启用</span><b data-n="${en}">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-warning">${ic('activity')}</span><div><span>近 30 天命中</span><b data-n="${hits}">0</b></div></div>
        <div class="mini"><span class="mini-ic mi-muted">${ic('shield')}</span><div><span>内置规则</span><b>${D.rules.filter(r => r.builtin).length}</b></div></div>
      </div>
      <div class="rl-wrap">
        <section class="card rl-list">
          <div class="rl-filter">${seg('cat', [['all', '全部'], ['pii', '个人'], ['fin', '金融'], ['cred', '凭证'], ['corp', '机密']], 'all')}
            <div class="search-box">${ic('search')}<input class="input" id="q" placeholder="搜索规则名称…"></div></div>
          <ul id="rlist"></ul>
        </section>
        <div class="rl-main">
          <section class="card" id="detail"></section>
          ${card('规则测试沙箱', `
            <div class="toolbar">${seg('scope', [['all', '全部已启用规则'], ['one', '仅当前规则']], 'all')}<span class="sp"></span><button class="btn btn-sm btn-ghost" id="resetTxt">${ic('refresh')}恢复示例文本</button></div>
            <div class="sbx">
              <div><label class="lbl">测试文本 <span class="hint">输入或粘贴内容，实时识别</span></label><textarea class="input sbx-in" id="txt" spellcheck="false">${esc(SAMPLE)}</textarea></div>
              <div><label class="lbl">识别结果 <span class="hint" id="mcnt"></span></label><div class="sbx-out" id="out"></div></div>
            </div>
            <div class="table-wrap" style="margin-top:14px"><table class="table compact-t"><thead><tr><th>#</th><th>命中规则</th><th>分类</th><th>命中内容（脱敏）</th><th>位置</th><th>校验</th></tr></thead><tbody id="mrows"></tbody></table></div>`,
            { id: 'sandbox', sub: '由服务端检测引擎（RE2）识别，测试文本不落盘、不写日志', extra: '<span class="pill pill-live">实时</span>' })}
        </div>
      </div>`;
    },
    mount(root) {
      const q = s => root.querySelector(s);
      let cat = 'all', kw = '', cur = D.rules[0].id, scope = 'all';
      $$('[data-n]', root).forEach(el => countUp(el, +el.dataset.n));

      function renderList() {
        const L = D.rules.filter(r => (cat === 'all' || r.cat === cat) && (!kw || r.name.toLowerCase().includes(kw.toLowerCase())));
        q('#rlist').innerHTML = L.length ? L.map((r, i) => `<li class="rl ${r.id === cur ? 'on' : ''} ${r.enabled ? '' : 'off'}" data-id="${r.id}" style="--i:${i};--c:var(--${CAT[r.cat][2]})">
          <span class="rl-ic">${ic(TYPE[r.type][1])}</span>
          <div class="rl-m"><b>${esc(r.name)}</b><small>${TYPE[r.type][0]} · ${r.builtin ? '内置' : '自定义'} · 命中 ${fmt(r.hits)}</small></div>
          <label class="switch sm"><input type="checkbox" data-sw ${r.enabled ? 'checked' : ''} ${UI.canDo('rules', 'cfg') ? '' : 'disabled'} aria-label="启用"><span></span></label></li>`).join('')
          : `<li class="empty-st">${ic('search')}<p>没有匹配的规则</p></li>`;
      }
      function renderDetail() {
        const r = D.rules.find(x => x.id === cur);
        const box = q('#detail');
        box.innerHTML = `<header class="card-h"><div><div class="dr-meta"><span class="tag ${CAT[r.cat][1]}">${CAT[r.cat][0]}</span><span class="tag">${ic(TYPE[r.type][1])}${TYPE[r.type][0]}</span><span class="mono muted small">${r.id}</span>${r.builtin ? '<span class="tag">内置</span>' : '<span class="tag b-info">自定义</span>'}</div>
          <h3 class="rl-title">${esc(r.name)}</h3><p>${esc(r.desc)}</p></div>
          <div class="card-x"><button class="btn btn-sm" data-dup>${ic('copy')}复制为自定义</button>${r.builtin ? '' : `<button class="btn btn-sm" data-edit>${ic('edit')}编辑</button>`}</div></header>
          <div class="card-b rl-body">${cfgHtml(r)}
            <div class="rl-kpis"><div><span>近 30 天命中</span><b>${fmt(r.hits)}</b></div><div><span>误报率</span><b class="${r.fp > 2 ? 'warn-c' : ''}">${r.hits ? r.fp + '%' : '-'}</b></div><div><span>来源</span><b>${r.builtin ? '内置' : '自定义'}</b></div><div><span>最近更新</span><b>${relTime(r.updated)}</b></div></div>
          </div>`;
        box.classList.remove('swap'); void box.offsetWidth; box.classList.add('swap');
        const sim = box.querySelector('#sim');
        sim && sim.addEventListener('input', e => { box.querySelector('#simV').textContent = e.target.value + '%'; });
        sim && sim.addEventListener('change', e => API.patch('/rules/' + encodeURIComponent(r.id), { sim: +e.target.value }).then(upd => { Object.assign(r, upd); toast(`相似度阈值已调整为 ${upd.cfg.sim}%`, { type: 'success' }); }).catch(UI.apiError));
      }
      let testSeq = 0;
      async function runTest() {
        const my = ++testSeq;
        const text = q('#txt').value;
        const ruleIds = scope === 'one' ? [cur] : [];
        let r;
        try { r = await API.post('/rules/test', { text, ruleIds }); } catch (e) { UI.apiError(e); return; }
        if (my !== testSeq || !root.isConnected) return;
        const byId = Object.fromEntries(D.rules.map(x => [x.id, x]));
        const ms = r.matches.filter(m => byId[m.ruleId]).map(m => ({ ...m, r: byId[m.ruleId] }));
        q('#out').innerHTML = highlight(text, ms) || '<span class="muted">（空）</span>';
        const valid = ms.filter(m => m.ok).length;
        q('#mcnt').textContent = `命中 ${valid} 处${ms.length - valid ? `，${ms.length - valid} 处未通过校验已忽略` : ''}`;
        const one = byId[cur];
        q('#mrows').innerHTML = ms.length ? ms.map((m, i) => `<tr class="${m.ok ? '' : 'dim'}" style="--i:${i}"><td class="muted">${i + 1}</td><td><b class="rn">${esc(m.r.name)}</b></td><td><span class="tag ${CAT[m.r.cat][1]}">${CAT[m.r.cat][0]}</span></td><td class="mono">${esc(mask(m.v))}</td><td class="muted mono">${m.s}–${m.e}</td><td>${m.r.cfg.check ? (m.ok ? `<span class="ok-t">${ic('check')}通过</span>` : `<span class="danger-t">${ic('x')}未通过</span>`) : '<span class="muted">—</span>'}</td></tr>`).join('')
          : `<tr><td colspan="6"><div class="empty-st" style="padding:24px 0">${ic('shield-check')}<p>${scope === 'one' && one && !['regex', 'keyword'].includes(one.type) ? `「${TYPE[one.type][0]}」类规则需在检测引擎中基于索引运行，沙箱仅支持正则与关键词` : '未识别到敏感内容'}</p></div></td></tr>`;
      }

      initSeg(root, 'cat', v => { cat = v; renderList(); });
      initSeg(root, 'scope', v => { scope = v; runTest(); });
      let t1; q('#q').addEventListener('input', e => { clearTimeout(t1); t1 = setTimeout(() => { kw = e.target.value.trim(); renderList(); }, 150); });
      q('#rlist').addEventListener('click', e => {
        const li = e.target.closest('.rl'); if (!li) return;
        const r = D.rules.find(x => x.id === li.dataset.id);
        if (e.target.closest('.switch')) {
          if (e.target.matches('[data-sw]')) {
            const sw = e.target, want = sw.checked;
            API.patch('/rules/' + encodeURIComponent(r.id), { enabled: want }).then(upd => {
              Object.assign(r, upd); li.classList.toggle('off', !r.enabled);
              toast(`规则「${esc(r.name)}」已${r.enabled ? '启用' : '停用'}，将在 1 分钟内下发至所有检测节点`, { type: r.enabled ? 'success' : 'warning' });
              runTest();
            }).catch(err => { sw.checked = !want; UI.apiError(err); });
          }
          return;
        }
        if (cur === r.id) return;
        cur = r.id; $$('.rl', root).forEach(x => x.classList.toggle('on', x.dataset.id === cur));
        renderDetail(); if (scope === 'one') runTest();
      });
      q('#detail').addEventListener('click', e => {
        const r = D.rules.find(x => x.id === cur);
        if (e.target.closest('[data-copy]')) { navigator.clipboard && navigator.clipboard.writeText(r.cfg.src).catch(() => {}); toast('正则表达式已复制到剪贴板', { type: 'success' }); }
        else if (e.target.closest('[data-sync]')) act(e.target.closest('[data-sync]'), () => API.post(`/rules/${encodeURIComponent(r.id)}/sync`), x => toast(`已从数据源同步 ${fmt(x.records)} 条记录，索引已更新`, { type: 'success', title: 'EDM 同步完成' }));
        else if (e.target.closest('[data-up]')) toast('样本文档上传需通过检测节点的指纹采集工具完成', { type: 'info' });
        else if (e.target.closest('[data-train]')) act(e.target.closest('[data-train]'), () => API.post(`/rules/${encodeURIComponent(r.id)}/train`), x => toast(`已基于 ${x.samples} 条误报反馈完成增量训练`, { type: 'success', title: '训练完成' }));
        else if (e.target.closest('[data-dup]')) openEditor({ ...r, name: r.name + '（副本）' });
        else if (e.target.closest('[data-edit]')) openEditor(r, true);
      });
      let t2; q('#txt').addEventListener('input', () => { clearTimeout(t2); t2 = setTimeout(runTest, 250); });
      q('#resetTxt').addEventListener('click', () => { q('#txt').value = SAMPLE; runTest(); });
      q('#newRule').addEventListener('click', () => openEditor(null));

      function openEditor(src, editing) {
        const r = src || { name: '', cat: 'pii', type: 'regex', cfg: { src: '' }, desc: '' };
        const isRe = r.type === 'regex';
        const { panel, close } = openLayer('modal', `
          <div class="md-head"><div><h2>${editing ? '编辑规则' : '新建识别规则'}</h2><p>自定义规则保存后将自动下发至全部检测节点</p></div><button class="icon-btn" data-close aria-label="关闭">${ic('x')}</button></div>
          <div class="md-body">
            <div class="field"><label class="lbl">规则名称 <em>*</em></label><input class="input" id="eName" value="${esc(r.name)}" placeholder="例如：员工工号"><div class="field-err" id="eNameErr">请输入规则名称</div></div>
            <div class="grid g2" style="margin-bottom:0">
              <div class="field"><label class="lbl">数据分类</label><select class="input" id="eCat">${Object.entries(CAT).map(([k, v]) => `<option value="${k}" ${k === r.cat ? 'selected' : ''}>${v[0]}</option>`).join('')}</select></div>
              <div class="field"><label class="lbl">规则类型</label><select class="input" id="eType"><option value="regex" ${isRe ? 'selected' : ''}>正则表达式</option><option value="keyword" ${r.type === 'keyword' ? 'selected' : ''}>关键词词典</option></select></div>
            </div>
            <div class="field"><label class="lbl" id="ePatL">${isRe || r.type !== 'keyword' ? '正则表达式' : '关键词（每行一个）'} <em>*</em><span class="hint" id="eHint"></span></label>
              <textarea class="input mono" id="ePat" rows="3" placeholder="例如：EMP-\\d{6}">${esc(r.type === 'keyword' ? r.cfg.words.join('\n') : (r.cfg.src || ''))}</textarea><div class="field-err" id="ePatErr"></div></div>
            <div class="field"><label class="lbl">快速验证 <span class="hint">输入示例文本</span></label><input class="input" id="eTry" value="员工 EMP-208431 的工单"><div class="try-r" id="eTryR"></div></div>
          </div>
          <div class="md-foot"><span class="sp"></span><button class="btn" data-close>取消</button><button class="btn btn-primary" data-ok>${ic('save')}保存并下发</button></div>`);
        const g = s => panel.querySelector(s);
        const check = () => {
          const type = g('#eType').value, pat = g('#ePat').value.trim(), err = g('#ePatErr');
          g('#ePatL').firstChild.textContent = type === 'regex' ? '正则表达式 ' : '关键词（每行一个） ';
          err.classList.remove('show'); g('#ePat').classList.remove('err');
          if (!pat) { g('#eTryR').innerHTML = ''; return null; }
          let rule;
          if (type === 'regex') {
            try { new RegExp(pat, 'g'); } catch (e) { err.textContent = '语法错误：' + e.message; err.classList.add('show'); g('#ePat').classList.add('err'); g('#eTryR').innerHTML = ''; return false; }
            rule = { type, cat: g('#eCat').value, name: '新规则', cfg: { src: pat } };
          } else rule = { type, cat: g('#eCat').value, name: '新规则', cfg: { words: pat.split('\n').map(s => s.trim()).filter(Boolean) } };
          const tx = g('#eTry').value, ms = findMatches(tx, [rule]);
          g('#eTryR').innerHTML = ms.length ? `${ic('check')}命中 ${ms.length} 处：${highlight(tx, ms)}` : `<span class="muted">${ic('x')}示例文本未命中</span>`;
          g('#eTryR').className = 'try-r ' + (ms.length ? 'hit' : '');
          return rule;
        };
        ['#ePat', '#eTry', '#eType', '#eCat'].forEach(s => g(s).addEventListener('input', check));
        check();
        g('[data-ok]').addEventListener('click', e => {
          const name = g('#eName').value.trim();
          if (!name) { g('#eName').classList.add('err', 'shake'); g('#eNameErr').classList.add('show'); setTimeout(() => g('#eName').classList.remove('shake'), 500); return; }
          const rule = check();
          if (!rule) { if (rule === null) { g('#ePatErr').textContent = '请填写规则内容'; g('#ePatErr').classList.add('show'); g('#ePat').classList.add('err'); } return; }
          const body = { name, cat: rule.cat, type: rule.type, cfg: rule.cfg };
          act(e.currentTarget, () => editing ? API.put('/rules/' + encodeURIComponent(src.id), body) : API.post('/rules', body), saved => {
            if (editing) Object.assign(src, saved); else D.rules.unshift(saved);
            cur = saved.id;
            close(); renderList(); renderDetail(); runTest();
            toast(`规则「${esc(saved.name)}」已保存并下发至检测节点`, { type: 'success', title: '保存成功' });
          }).then(r2 => { if (r2 === undefined) { g('#ePat').classList.add('err'); } });
        });
      }

      renderList(); renderDetail(); runTest();
      if (UI.params.get('test')) setTimeout(() => { q('#sandbox').scrollIntoView({ behavior: 'smooth', block: 'start' }); q('#txt').focus({ preventScroll: true }); }, 300);
    }
  };
})();
