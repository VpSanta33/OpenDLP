/* ==========================================================================
   API 客户端：同源 Cookie 会话 + 自定义请求头（CSRF 防护），统一错误处理与 SSE 实时推送
   ========================================================================== */
(function () {
  'use strict';
  const BASE = '/api/v1';

  async function req(method, url, body, opt) {
    const o = opt || {};
    const headers = { 'X-OpenDLP-Request': '1', Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch(BASE + url, { method, headers, credentials: 'same-origin', body: body === undefined ? undefined : JSON.stringify(body) });
    } catch (e) {
      const err = new Error('无法连接管理服务，请检查网络或服务是否启动'); err.status = 0; throw err;
    }
    let data = null;
    if ((res.headers.get('content-type') || '').includes('json')) data = await res.json().catch(() => null);
    if (!res.ok) {
      const err = new Error((data && data.error) || `请求失败（HTTP ${res.status}）`);
      err.status = res.status; err.data = data;
      if (res.status === 401 && !o.quiet401 && API.onUnauthorized) API.onUnauthorized(err);
      if (res.status === 403 && data && data.code === 'pwd_change' && API.onPwdChange) API.onPwdChange(err);
      throw err;
    }
    return data;
  }

  /* SSE：事件统一转发到 UI 事件总线；连接被服务端拒绝时回调 onClosed */
  let es = null;
  function stream(emit, onClosed) {
    close();
    es = new EventSource(BASE + '/stream');
    ['incident', 'note', 'nodes', 'fleet', 'incidents.changed', 'approvals.changed', 'reports.changed'].forEach(n =>
      es.addEventListener(n, e => { try { emit(n, JSON.parse(e.data)); } catch (err) { console.error(err); } }));
    es.addEventListener('logout', () => { close(); onClosed && onClosed(); });
    es.onerror = () => { if (es && es.readyState === EventSource.CLOSED) { close(); onClosed && onClosed(); } };
  }
  function close() { if (es) { es.close(); es = null; } }

  /* 触发浏览器下载（服务端返回 Content-Disposition: attachment） */
  function download(url) {
    const a = document.createElement('a');
    a.href = url.startsWith('/') ? url : BASE + url; a.rel = 'noopener';
    document.body.appendChild(a); a.click(); a.remove();
  }

  const API = window.API = {
    req,
    get: (u, o) => req('GET', u, undefined, o),
    post: (u, b, o) => req('POST', u, b === undefined ? {} : b, o),
    put: (u, b) => req('PUT', u, b),
    patch: (u, b) => req('PATCH', u, b),
    del: u => req('DELETE', u),
    stream, closeStream: close, download,
    qs: o => { const p = new URLSearchParams(); Object.entries(o).forEach(([k, v]) => { if (v !== '' && v != null && v !== 'all') p.set(k, v); }); const s = p.toString(); return s ? '?' + s : ''; },
    onUnauthorized: null
  };
})();
