// Vanishly - starts the API reference (Scalar) on /api/docs with the OpenAPI
// document. Everything comes from this server: no web fonts, no proxy, no AI
// agent; light or dark follows the visitor's choice on the other pages.
let dark = matchMedia('(prefers-color-scheme: dark)').matches;
try {
  const mode = localStorage.getItem('vanishly-mode');
  if (mode === 'dark' || mode === 'light') dark = mode === 'dark';
} catch {
  // storage blocked: system setting
}
/** @type {any} */ (window).Scalar.createApiReference('#docs', {
  sources: [{ url: '/api/openapi.json', slug: 'vanishly', title: 'Vanishly API', default: true }],
  withDefaultFonts: false,
  // System fonts, so the page asks no font server (the CSP would block it).
  customCss: ':root, .scalar-app { --scalar-font: system-ui, sans-serif; --scalar-font-code: ui-monospace, monospace; }' +
    // No advertising for Scalar's paid services.
    ' div:has(> .explore-scalar-cta) { display: none; }' +
    // No "Powered by Scalar" link (MIT asks for no visible credit); the light/dark switch next to it stays.
    ' .darklight-reference a[href*="scalar.com"] { display: none; }',
  proxyUrl: '',
  telemetry: false,
  agent: { disabled: true },
  mcp: { disabled: true },
  showDeveloperTools: 'never',
  hideClientButton: true,
  darkMode: dark,
  defaultOpenAllTags: true,
});
