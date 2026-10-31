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

function parsePagination(url) {
  let page = parseInt(url.searchParams.get('page') || '1', 10)
  let pageSize = parseInt(url.searchParams.get('pageSize') || '25', 10)
  if (!Number.isFinite(page) || page < 1) page = 1
  if (!Number.isFinite(pageSize) || pageSize < 1) pageSize = 25
  if (pageSize > 100) pageSize = 100
  return { page, pageSize, offset: (page - 1) * pageSize }
}

function escapeLike(value) {
  return String(value).replace(/\\/g, '\\\\').replace(/%/g, '\\%').replace(/_/g, '\\_')
}

function validDateRange(url) {
  const from = url.searchParams.get('from') || ''
  const to = url.searchParams.get('to') || ''
  const iso = /^\d{4}-\d{2}-\d{2}$/
  const now = new Date()
  const toDate = to && iso.test(to) ? to : now.toISOString().slice(0, 10)
  const fromDate = from && iso.test(from) ? from : new Date(now.getTime() - 30 * 24 * 3600 * 1000).toISOString().slice(0, 10)
  if (fromDate > toDate) return null
  const days = Math.round((new Date(toDate).getTime() - new Date(fromDate).getTime()) / (24 * 3600 * 1000))
  if (days < 0 || days > 365) return null
  return { from: `${fromDate}T00:00:00.000Z`, to: `${toDate}T23:59:59.999Z` }
}

async function handleOverview(env, url) {
  const range = validDateRange(url)
  if (!range) return null
  const usersTotal = await env.DB.prepare('SELECT COUNT(*) AS c FROM users').first()
  const usersByStatus = await env.DB.prepare('SELECT status, COUNT(*) AS c FROM users GROUP BY status ORDER BY c DESC').all()
  const mfaCount = await env.DB.prepare('SELECT COUNT(*) AS c FROM users WHERE mfa_enabled = 1').first()
  const newUsers = await env.DB.prepare('SELECT COUNT(*) AS c FROM users WHERE created_at >= ? AND created_at <= ?').bind(range.from, range.to).first()
  const byPlan = await env.DB.prepare('SELECT plan, COUNT(*) AS c FROM entitlements GROUP BY plan ORDER BY c DESC').all()
  const byEntStatus = await env.DB.prepare('SELECT status, COUNT(*) AS c FROM entitlements GROUP BY status ORDER BY c DESC').all()
  const companiesTotal = await env.DB.prepare('SELECT COUNT(*) AS c FROM companies').first()
  const memberships = await env.DB.prepare('SELECT COUNT(*) AS c FROM company_members').first()
  const activeSessions = await env.DB.prepare("SELECT COUNT(*) AS c FROM sessions WHERE expires_at > datetime('now')").first()
  return {
    users: {
      total: usersTotal ? usersTotal.c : 0,
      byStatus: (usersByStatus.results || []).map((r) => ({ status: r.status, count: r.c })),
      mfaEnabled: mfaCount ? mfaCount.c : 0,
      newInRange: newUsers ? newUsers.c : 0,
    },
    plans: {
      byPlan: (byPlan.results || []).map((r) => ({ plan: r.plan, count: r.c })),
      byStatus: (byEntStatus.results || []).map((r) => ({ status: r.status, count: r.c })),
    },
    companies: {
      total: companiesTotal ? companiesTotal.c : 0,
      memberships: memberships ? memberships.c : 0,
    },
    sessionsActive: activeSessions ? activeSessions.c : 0,
    payments: null,
  }
}

async function handleUsers(env, url) {
  const { page, pageSize, offset } = parsePagination(url)
  const q = (url.searchParams.get('q') || '').trim()
  const plan = url.searchParams.get('plan') || ''
  const status = url.searchParams.get('status') || ''
  const where = []
  const params = []
  if (q) {
    where.push('(u.id = ? OR u.email_normalized LIKE ? ESCAPE \'\\\' OR u.first_name LIKE ? ESCAPE \'\\\' OR u.last_name LIKE ? ESCAPE \'\\\')')
    const like = `%${escapeLike(q.toLowerCase())}%`
    params.push(q, like, `%${escapeLike(q)}%`, `%${escapeLike(q)}%`)
  }
  if (plan) {
    where.push('e.plan = ?')
    params.push(plan)
  }
  if (status) {
    where.push('u.status = ?')
    params.push(status)
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''
  const rows = await env.DB.prepare(
    `SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.status, u.email_verified, u.mfa_enabled, u.created_at, e.plan, e.status AS plan_status, e.current_period_end FROM users u LEFT JOIN entitlements e ON e.user_id = u.id ${whereSql} ORDER BY u.created_at DESC LIMIT ? OFFSET ?`,
  ).bind(...params, pageSize, offset).all()
  const totalRow = await env.DB.prepare(
    `SELECT COUNT(*) AS c FROM users u LEFT JOIN entitlements e ON e.user_id = u.id ${whereSql}`,
  ).bind(...params).first()
  return { page, pageSize, total: totalRow ? totalRow.c : 0, users: rows.results || [] }
}

async function handleUserDetail(env, userId) {
  const user = await env.DB.prepare(
    'SELECT u.id, u.email, u.first_name, u.last_name, u.phone, u.status, u.email_verified, u.mfa_enabled, u.created_at, u.updated_at, e.plan, e.status AS plan_status, e.provider, e.provider_subscription_id, e.current_period_end, e.updated_at AS entitlement_updated_at FROM users u LEFT JOIN entitlements e ON e.user_id = u.id WHERE u.id = ?',
  ).bind(userId).first()
  if (!user) return null
  const owned = await env.DB.prepare('SELECT id, name, created_at, updated_at FROM companies WHERE owner_user_id = ? ORDER BY created_at DESC').bind(userId).all()
  const memberships = await env.DB.prepare(
    'SELECT m.company_id, m.role, m.status, m.joined_at, c.name AS company_name FROM company_members m JOIN companies c ON c.id = m.company_id WHERE m.user_id = ? ORDER BY m.joined_at DESC',
  ).bind(userId).all()
  const lastLogin = await env.DB.prepare("SELECT MAX(created_at) AS last_login FROM audit_events WHERE user_id = ? AND event_type = 'login' AND ok = 1").bind(userId).first()
  const audit = await env.DB.prepare('SELECT event_type, ok, detail, created_at FROM audit_events WHERE user_id = ? ORDER BY created_at DESC LIMIT 20').bind(userId).all()
  return {
    user,
    ownedCompanies: owned.results || [],
    memberships: memberships.results || [],
    lastLogin: lastLogin ? lastLogin.last_login : null,
    recentAudit: (audit.results || []).map((r) => ({ event_type: r.event_type, ok: r.ok, detail: r.detail, created_at: r.created_at })),
  }
}

async function handleCompanies(env, url) {
  const { page, pageSize, offset } = parsePagination(url)
  const rows = await env.DB.prepare(
    'SELECT c.id, c.name, c.owner_user_id, u.email AS owner_email, c.created_at, c.updated_at, (SELECT COUNT(*) FROM company_members m WHERE m.company_id = c.id) AS member_count FROM companies c LEFT JOIN users u ON u.id = c.owner_user_id ORDER BY c.created_at DESC LIMIT ? OFFSET ?',
  ).bind(pageSize, offset).all()
  const totalRow = await env.DB.prepare('SELECT COUNT(*) AS c FROM companies').first()
  return { page, pageSize, total: totalRow ? totalRow.c : 0, companies: rows.results || [] }
}

async function handleAuditLog(env, url) {
  const { page, pageSize, offset } = parsePagination(url)
  const admin = (url.searchParams.get('admin') || '').trim()
  const action = (url.searchParams.get('action') || '').trim()
  const resource = (url.searchParams.get('resource') || '').trim()
  const outcome = url.searchParams.get('outcome') || ''
  const range = validDateRange(url)
  const where = []
  const params = []
  if (admin) {
    where.push('admin_user_id = ?')
    params.push(admin)
  }
  if (action) {
    where.push('action = ?')
    params.push(action)
  }
  if (resource) {
    where.push('resource_id = ?')
    params.push(resource)
  }
  if (outcome === 'success' || outcome === 'failure') {
    where.push('success = ?')
    params.push(outcome === 'success' ? 1 : 0)
  }
  if (range) {
    where.push('created_at >= ? AND created_at <= ?')
    params.push(range.from, range.to)
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''
  const rows = await env.DB.prepare(
    `SELECT id, admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at FROM admin_audit_log ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  ).bind(...params, pageSize, offset).all()
  const totalRow = await env.DB.prepare(
    `SELECT COUNT(*) AS c FROM admin_audit_log ${whereSql}`,
  ).bind(...params).first()
  return { page, pageSize, total: totalRow ? totalRow.c : 0, entries: rows.results || [] }
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

async function checkReadRate(db, endpoint, ipHash, nowMs) {
  const windowStart = Math.floor(nowMs / 60000)
  await db
    .prepare('INSERT INTO rate_limits (key, window_start, count, updated_at) VALUES (?, ?, 1, ?) ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at')
    .bind(`admin-read:${endpoint}:ip:${ipHash}`, windowStart, new Date(nowMs).toISOString())
    .run()
  const row = await db
    .prepare('SELECT count FROM rate_limits WHERE key = ? AND window_start = ?')
    .bind(`admin-read:${endpoint}:ip:${ipHash}`, windowStart)
    .first()
  return !!row && row.count <= 60
}

async function handleRead(request, env, origin, endpoint, handler) {
  const ip = request.headers.get('CF-Connecting-IP') || ''
  const ipHash = await sha256Hex(ip)
  try {
    const allowed = await checkReadRate(env.DB, endpoint, ipHash, Date.now())
    if (!allowed) return errorResponse(origin, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
  const { auth, error } = await authenticate(request, env, origin)
  if (error) {
    try {
      await audit(env.DB, '', 'admin_access_denied', 'api', endpoint, '', false)
    } catch {
      // Denial audit is best-effort for reads; the denial itself stands.
    }
    return error
  }
  try {
    const data = await handler(env)
    if (data === null) return errorResponse(origin, 404, 'Not found.', 'NOT_FOUND')
    return jsonResponse(origin, 200, { ok: true, ...data })
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
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
    if (method === 'GET' && path === '/api/overview') {
      if (!validDateRange(url)) return errorResponse(origin, 400, 'Invalid date range.', 'INVALID_RANGE')
      return handleRead(request, env, origin, 'overview', async (dbEnv) => handleOverview(dbEnv, url))
    }
    if (method === 'GET' && path === '/api/users') {
      return handleRead(request, env, origin, 'users', async (dbEnv) => handleUsers(dbEnv, url))
    }
    if (method === 'GET' && path.startsWith('/api/users/')) {
      const userId = decodeURIComponent(path.slice('/api/users/'.length))
      if (!userId || userId.length > 128 || userId.includes('/')) return errorResponse(origin, 400, 'Invalid user id.', 'INVALID_ID')
      return handleRead(request, env, origin, 'user-detail', async (dbEnv) => handleUserDetail(dbEnv, userId))
    }
    if (method === 'GET' && path === '/api/companies') {
      return handleRead(request, env, origin, 'companies', async (dbEnv) => handleCompanies(dbEnv, url))
    }
    if (method === 'GET' && path === '/api/audit-log') {
      return handleRead(request, env, origin, 'audit-log', async (dbEnv) => handleAuditLog(dbEnv, url))
    }
    if (path === '/api/health' || path === '/api/auth/verify' || path === '/api/overview' || path === '/api/users' || path.startsWith('/api/users/') || path === '/api/companies' || path === '/api/audit-log') {
      return errorResponse(origin, 405, 'Method not allowed.', 'METHOD_NOT_ALLOWED')
    }
    return errorResponse(origin, 404, 'Not found.', 'NOT_FOUND')
  },
}
