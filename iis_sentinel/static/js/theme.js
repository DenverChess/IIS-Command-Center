/* Applies the saved UI theme before first paint (no inline scripts: the CSP is script-src 'self'). */
(function () {
  var t = "cyber";
  try {
    t = localStorage.getItem("sentinel.theme") || localStorage.getItem("sentinel.default_theme") || "cyber";
  } catch (_) { /* storage blocked: keep the default */ }
  if (["cyber", "dark", "lite", "large"].indexOf(t) < 0) t = "cyber";
  document.documentElement.setAttribute("data-theme", t);
})();
