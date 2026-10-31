const enc = new TextEncoder()

export function b64urlDecode(s) {
  const norm = String(s).replace(/-/g, '+').replace(/_/g, '/')
  const padded = norm + '='.repeat((4 - (norm.length % 4)) % 4)
  const bin = atob(padded)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i)
  return bytes
}

export function b64urlEncode(bytes) {
  let s = ''
  const chunk = 0x8000
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode(...bytes.subarray(i, i + chunk))
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '')
}

export function parseAssertion(token) {
  try {
    if (typeof token !== 'string') return null
    const parts = token.split('.')
    if (parts.length !== 3) return null
    const header = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[0])))
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(parts[1])))
    if (!header || !payload) return null
    return { header, payload, signature: b64urlDecode(parts[2]), signingInput: `${parts[0]}.${parts[1]}` }
  } catch {
    return null
  }
}

export async function verifyAssertion(token, publicKeysByKid, nowMs = Date.now()) {
  const parsed = parseAssertion(token)
  if (!parsed) return { ok: false, error: 'Malformed assertion.' }
  const { header, payload, signature, signingInput } = parsed
  if (header.alg !== 'EdDSA') return { ok: false, error: 'Unsupported signing algorithm.' }
  if (typeof header.kid !== 'string' || !header.kid) return { ok: false, error: 'Missing key id.' }
  const jwk = publicKeysByKid[header.kid]
  if (!jwk) return { ok: false, error: 'Unknown key id.' }
  if (typeof payload.sub !== 'string' || !payload.sub) return { ok: false, error: 'Missing subject.' }
  if (typeof payload.sid !== 'string' || !payload.sid) return { ok: false, error: 'Missing session id.' }
  if (payload.aud !== 'kluzar-admin-api') return { ok: false, error: 'Wrong audience.' }
  const nowSec = Math.floor(nowMs / 1000)
  if (typeof payload.iat !== 'number' || typeof payload.exp !== 'number') return { ok: false, error: 'Missing timestamps.' }
  if (payload.iat > nowSec + 30) return { ok: false, error: 'Assertion issued in the future.' }
  if (payload.exp <= nowSec) return { ok: false, error: 'Assertion expired.' }
  if (payload.exp - payload.iat > 600) return { ok: false, error: 'Assertion lifetime too long.' }
  let key
  try {
    key = await crypto.subtle.importKey('jwk', jwk, { name: 'Ed25519' }, false, ['verify'])
  } catch {
    return { ok: false, error: 'Invalid verification key.' }
  }
  let valid = false
  try {
    valid = await crypto.subtle.verify({ name: 'Ed25519' }, key, signature, enc.encode(signingInput))
  } catch {
    valid = false
  }
  if (!valid) return { ok: false, error: 'Bad signature.' }
  return { ok: true, payload }
}

export async function signAssertionForTest(privateJwk, claims, kid = 'admin-assertion-v1') {
  const header = { alg: 'EdDSA', typ: 'JWT', kid }
  const h = b64urlEncode(enc.encode(JSON.stringify(header)))
  const p = b64urlEncode(enc.encode(JSON.stringify(claims)))
  const key = await crypto.subtle.importKey('jwk', privateJwk, { name: 'Ed25519' }, false, ['sign'])
  const sig = await crypto.subtle.sign({ name: 'Ed25519' }, key, enc.encode(`${h}.${p}`))
  return `${h}.${p}.${b64urlEncode(new Uint8Array(sig))}`
}
