/* 首帧前应用主题与界面偏好，避免闪烁（独立文件以满足 CSP：script-src 'self'） */
(function () {
  var g = function (k) { try { return JSON.parse(localStorage.getItem('odlp.' + k)); } catch (e) { return null; } };
  var h = document.documentElement, t = g('theme');
  if (!t || t === 'system') t = window.matchMedia && matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  h.dataset.theme = t;
  if (g('side') && g('side') !== 'theme') h.dataset.side = g('side');
  if (g('accent') && g('accent') !== 'blue') h.dataset.accent = g('accent');
  if (g('density') === 'compact') h.dataset.density = 'compact';
})();
