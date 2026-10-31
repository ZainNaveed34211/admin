import { verifyAssertion } from './verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const ADMIN_AUD = 'kluzar-admin-api'
const ADMIN_KID = 'admin-assertion-v1'
const VERIFY_LIMIT = 20
const VERIFY_WINDOW_MS = 10 * 60 * 1000

function corsHeaders(origin) {
  const headers = {
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Credentials': 'false',
    Vary: 'Origin',
  }
  if (origin === ADMIN_ORIGIN) headers['Access-Control-Allow-Origin'] = origin
  return headers
}

function securityHeaders() {
  return {
    'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
    'Cache-Control': 'no-store',
  }
}

function jsonResponse(origin, status, body) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json', ...securityHeaders(), ...corsHeaders(origin) },
  })
}

function errorResponse(origin, status, message, code) {
  return jsonResponse(origin, status, { ok: false, error: message, code })
}

function publicKeysByKid(env) {
  const map = {}
  try {
    if (env.ADMIN_ASSERTION_PUBLIC_KEY) {
      map[ADMIN_KID] = JSON.parse(env.ADMIN_ASSERTION_PUBLIC_KEY)
    }
  } catch {
    // Misconfigured key fails closed below (unknown kid).
  }
  return map
}

async function sha256Hex(text) {
  const bytes = new TextEncoder().encode(text)
  const digest = await crypto.subtle.digest('SHA-256', bytes)
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('')
}

async function checkRateD1(db, ipHash, nowMs) {
  const windowStart = Math.floor(nowMs / VERIFY_WINDOW_MS)
  await db
    .prepare('INSERT INTO rate_limits (key, window_start, count, updated_at) VALUES (?, ?, 1, ?) ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at')
    .bind(`admin-verify:ip:${ipHash}`, windowStart, new Date(nowMs).toISOString())
    .run()
  const row = await db
    .prepare('SELECT count FROM rate_limits WHERE key = ? AND window_start = ?')
    .bind(`admin-verify:ip:${ipHash}`, windowStart)
    .first()
  return !!row && row.count <= VERIFY_LIMIT
}

async function audit(db, adminUserId, action, resourceType, resourceId, reason, success) {
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  await db
    .prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .bind(adminUserId, action, resourceType, resourceId, reason, success ? 1 : 0, correlationId, nowIso)
    .run()
  return correlationId
}

async function authenticate(request, env, origin) {
  if (origin !== ADMIN_ORIGIN) return { auth: null, error: errorResponse(origin, 403, 'Request not allowed.', 'FORBIDDEN') }
  const header = request.headers.get('Authorization') || ''
  const match = header.match(/^Bearer\s+(.+)$/)
  if (!match) return { auth: null, error: errorResponse(origin, 401, 'Missing or invalid authorization.', 'UNAUTHORIZED') }
  const verified = await verifyAssertion(match[1], publicKeysByKid(env))
  if (!verified.ok) return { auth: null, error: errorResponse(origin, 401, verified.error, 'UNAUTHORIZED') }
  const { sub, sid } = verified.payload
  const session = await env.DB.prepare(
    'SELECT s.*, u.status AS user_status, u.email AS user_email FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ? AND s.user_id = ?',
  ).bind(sid, sub).first()
  if (!session) return { auth: null, error: errorResponse(origin, 401, 'Session no longer exists.', 'UNAUTHORIZED') }
  if (new Date(session.expires_at).getTime() <= Date.now()) {
    return { auth: null, error: errorResponse(origin, 401, 'Session expired.', 'UNAUTHORIZED') }
  }
  if (session.user_status !== 'active') return { auth: null, error: errorResponse(origin, 401, 'Account is not active.', 'UNAUTHORIZED') }
  if (verified.payload.mfa !== true) return { auth: null, error: errorResponse(origin, 403, 'MFA is required for admin access.', 'MFA_REQUIRED') }
  const allowRow = await env.DB.prepare(
    'SELECT user_id FROM admin_allowlist WHERE user_id = ? AND role = ?',
  ).bind(sub, 'super_admin').first()
  if (!allowRow) return { auth: null, error: errorResponse(origin, 403, 'Admin access is not granted for this account.', 'FORBIDDEN') }
  return { auth: { userId: sub, email: session.user_email || '' }, error: null }
}

async function handleVerify(request, env, origin) {
  const ip = request.headers.get('CF-Connecting-IP') || ''
  const ipHash = await sha256Hex(ip)
  let allowed
  try {
    allowed = await checkRateD1(env.DB, ipHash, Date.now())
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
  if (!allowed) return errorResponse(origin, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
  const { auth, error } = await authenticate(request, env, origin)
  if (error) {
    try {
      await audit(env.DB, '', 'admin_verify_denied', 'auth', '', error.status === 403 ? 'forbidden' : 'unauthorized', false)
    } catch {
      return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
    }
    return error
  }
  try {
    await audit(env.DB, auth.userId, 'admin_login', 'auth', auth.userId, '', true)
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
  return jsonResponse(origin, 200, { ok: true, admin: true, userId: auth.userId, email: auth.email })
}

export default {
  async fetch(request, env) {
    const origin = request.headers.get('Origin') || ''
    const url = new URL(request.url)
    const path = url.pathname
    const method = request.method
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { ...securityHeaders(), ...corsHeaders(origin) } })
    }
    if (method === 'GET' && path === '/api/health') {
      if (origin !== ADMIN_ORIGIN) return errorResponse(origin, 403, 'Request not allowed.', 'FORBIDDEN')
      return jsonResponse(origin, 200, { ok: true, service: 'kluzar-admin-api' })
    }
    if (method === 'POST' && path === '/api/auth/verify') {
      return handleVerify(request, env, origin)
    }
    if (path === '/api/health' || path === '/api/auth/verify') {
      return errorResponse(origin, 405, 'Method not allowed.', 'METHOD_NOT_ALLOWED')
    }
    return errorResponse(origin, 404, 'Not found.', 'NOT_FOUND')
  },
}
