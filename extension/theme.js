// Apply theme ASAP to avoid a flash (system default; override from this
// page's own localStorage — no special permission needed).
// External file so it complies with the extension page CSP (no inline scripts).
(function () {
  var t = 'auto';
  try {
    var saved = localStorage.getItem('ps-theme');
    if (saved === 'light' || saved === 'dark') t = saved;
  } catch (_e) {}
  var resolved = t;
  if (t === 'auto') resolved = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', resolved);
})();