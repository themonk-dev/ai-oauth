/**
 * Scrubs credentials out of text before it goes into an error message.
 *
 * Error messages end up in application logs, crash reporters and terminal
 * scrollback. We embed a snippet of the provider's response body when a token
 * request fails, which is genuinely useful for diagnosis — but the body is not
 * ours and cannot be trusted to be credential-free. A misconfigured gateway
 * echoing the request back would put a live `refresh_token` straight into the
 * consumer's logs.
 *
 * This is defence in depth, not a guarantee: it recognises the OAuth parameter
 * names and the token shapes the supported providers actually issue. Never rely
 * on it to make an arbitrary secret safe to print.
 */

/** OAuth parameters whose values are credentials, in JSON or form encoding. */
const SECRET_PARAMS = [
  'access_token',
  'refresh_token',
  'id_token',
  'client_secret',
  'code_verifier',
  'device_code',
  'token',
  'code',
  'assertion',
]

/**
 * Matches key, optional quotes, `:` or `=`, optional quotes, then the value up
 * to a delimiter — covering `{"refresh_token":"x"}` and `refresh_token=x&…`
 * alike.
 *
 * Every quote may be preceded by a backslash, because the body we are handed is
 * routinely a *quoted* copy of another one. A gateway that echoes the request it
 * proxied puts it inside a JSON string of its own, so what actually arrives here
 * reads `{"upstream":"received {\"refresh_token\":\"rt-…\"}"}` — and this
 * pattern only ever sees the outer document's raw text, never the unescaped
 * value, because the snippet is scrubbed as text before anyone parses it. Made
 * to require a bare quote, the `[:=]` landed on the backslash instead, the match
 * failed, and a live refresh token went into the `OAuthError` message that
 * `safeSnippet` builds and from there into the consumer's logs. The escaping can
 * nest arbitrarily deep; one level is what a reflecting gateway produces and is
 * as far as this goes.
 *
 * The optional `[` covers the other shape the same failure took: a value written
 * as a one-element array, `{"refresh_token":["rt-…"]}`. Without it the bracket
 * was taken as the first character of the value and the quote right behind it
 * ended the value one character in, below the `{4,}` floor, so nothing matched
 * at all. It stays inside the captured prefix, so the redacted text still shows
 * that an array was there. A second element in that array is not covered — it
 * carries no key of its own to anchor on, and inventing one would mean matching
 * bare quoted strings anywhere, which is exactly the over-reach this pattern is
 * shaped to avoid.
 *
 * `\` is deliberately absent from the value class. That class is the only thing
 * stopping the value running past its own terminator; admitting a backslash
 * would let it swallow the closing `\"` and keep going through whatever followed
 * it, redacting the rest of the diagnostic along with the secret.
 */
const PARAM_PATTERN = new RegExp(
  String.raw`(\\?["']?\b(?:${SECRET_PARAMS.join('|')})\b\\?["']?\s*[:=]\s*\[?\s*)\\?["']?([^"'&,}\s]{4,})\\?["']?`,
  'gi',
)

/** Token shapes the supported providers issue, in case they appear bare. */
const TOKEN_SHAPES: { issuer: string; pattern: RegExp }[] = [
  { issuer: 'Authorization header value', pattern: /\bBearer\s+[\w.~+/=-]{8,}/gi },
  { issuer: 'Claude', pattern: /\bsk-ant-[\w-]{8,}/gi },
  { issuer: 'OpenRouter', pattern: /\bsk-or-v1-[\w-]{8,}/gi },
  { issuer: 'OpenAI', pattern: /\bsk-[A-Za-z0-9_-]{16,}/g },
  { issuer: 'GitHub', pattern: /\bgh[pousr]_[A-Za-z0-9]{16,}/g },
  { issuer: 'Gemini', pattern: /\bya29\.[\w.-]{8,}/g },
  {
    issuer: 'JWT',
    pattern: /\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*/g,
  },
]

export const REDACTED = '[redacted]'

export function redactSecrets(text: string): string {
  let out = text.replace(PARAM_PATTERN, (_match, prefix: string) => `${prefix}${REDACTED}`)

  for (const { pattern } of TOKEN_SHAPES) {
    out = out.replace(pattern, REDACTED)
  }

  return out
}

/**
 * Prepares an untrusted response body for inclusion in an error message:
 * redacted, collapsed onto one line, and truncated.
 */
export function safeSnippet(text: string, maxLength = 200): string {
  const collapsed = redactSecrets(text).replace(/\s+/g, ' ').trim()

  return collapsed.length > maxLength ? `${collapsed.slice(0, maxLength)}…` : collapsed
}
