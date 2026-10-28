// Vanishly - applies the light/dark mode before the page paints (no flash).
// Order: the visitor's choice (localStorage), the template's defaultMode,
// the system setting.
(function () {
  var root = document.documentElement;
  var mode = null;
  // Without the toggle (ENABLE_THEME_TOGGLE=false) an old choice no longer counts.
  if (root.getAttribute('data-mode-toggle') !== '0') {
    try {
      mode = localStorage.getItem('vanishly-mode');
    } catch (e) {}
  }
  if (mode !== 'light' && mode !== 'dark') {
    var def = root.getAttribute('data-default-mode');
    mode = def === 'light' || def === 'dark'
      ? def
      : window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  root.setAttribute('data-theme', mode);
})();
