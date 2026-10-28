// Vanishly - passphrase complexity rules, shared by the browser
// (public/js/app.js) and the server (POST /api/v1/share).

/** Character classes; Unicode-aware, so "Ä" is upper case and "٣" a digit. */
export const CLASSES = /** @type {const} */ ({
  upper: /\p{Lu}/u,
  lower: /\p{Ll}/u,
  digit: /\p{Nd}/u,
  symbol: /[^\p{L}\p{N}\s]/u,
});

/**
 * The classes a passphrase still lacks.
 * @param {string} pass
 * @param {string[]} classes
 */
export function missingClasses(pass, classes) {
  return classes.filter((c) => !CLASSES[/** @type {keyof typeof CLASSES} */ (c)]?.test(pass));
}
