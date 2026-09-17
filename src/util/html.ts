// The engine's single HTML-escaping helper, used by the transactional email HTML in email-theme.ts.
// One definition so the escape set can never diverge between call sites: if a metacharacter is added
// here, every HTML surface inherits it. It mirrors the control-plane's lib/html.ts escape set exactly,
// so the two mail surfaces neutralise the same five characters.

// HTML_ESCAPES maps the five HTML metacharacters to their entity forms. escapeHtml neutralises them so
// a substituted value can never inject markup. The values the engine emails carry (an event enum, a
// downpipe name, a sign-in URL) hold none of them today; escaping is defence in depth so a future
// field is safe by construction.
const HTML_ESCAPES: Record<string, string> = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };

/**
 * Escapes the five HTML metacharacters (`&`, `<`, `>`, `"`, `'`) to their entity forms.
 *
 * Coerces with `String(s ?? "")` first: callers are typed to pass a string, but a value read back off
 * storage can be wrong-typed or missing (the type is a compile-time promise, not a runtime guarantee),
 * and `undefined.replace` would otherwise throw. Coercing here makes a single stray value render as
 * text instead of throwing.
 *
 * @param s - the string to escape.
 * @returns `s` with every HTML metacharacter replaced by its entity, safe to interpolate into markup.
 */
export function escapeHtml(s: string): string {
  return String(s ?? "").replace(/[&<>"']/g, (c) => HTML_ESCAPES[c] ?? c);
}
