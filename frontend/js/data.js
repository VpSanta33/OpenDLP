/* ==========================================================================
   数据层：登录后由后端 /api/v1/bootstrap 填充，页面同步读取。
   各集合仅包含当前角色有权查看的数据；写操作统一经 API 提交后再更新本地副本。
   ========================================================================== */
(function () {
  'use strict';
  const EMPTY = () => ({
    NOW: Date.now(), users: [], employees: [], depts: [], deptLeaders: {}, channels: [], chMap: {}, dataTypes: [], dtMap: {},
    policies: [], incidents: [], endpoints: [], fleet: { licensed: 0, deployed: 0, online: 0 }, auditTypes: [], repos: [], notes: [],
    approvals: [], approvers: [], rules: [], roles: [], perms: {}, admins: [], nodes: [], integrations: [],
    reportSchedules: [], reportHistory: [], settings: {}, watchlist: [], LEVEL: {}
  });
  const D = window.DLP = EMPTY();

  /* 用后端引导数据整体替换（保持 window.DLP 引用不变，页面闭包中的 D 依然有效） */
  D.load = function (b) {
    const fresh = EMPTY();
    Object.keys(fresh).forEach(k => { D[k] = fresh[k]; });
    Object.keys(b).forEach(k => { if (k !== 'me') D[k] = b[k] == null ? D[k] : b[k]; });
    D.NOW = b.now || Date.now();
    D.LEVEL = b.level || {};
    D.chMap = Object.fromEntries(D.channels.map(c => [c.key, c]));
    D.dtMap = Object.fromEntries(D.dataTypes.map(t => [t.key, t]));
  };
  D.reset = () => D.load({});
})();
