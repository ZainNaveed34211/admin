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
  if (session.scope !== 'admin') return { auth: null, error: errorResponse(origin, 403, 'Admin session required.', 'FORBIDDEN') }
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

function auditLogFilters(url) {
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
  return { whereSql, params }
}

async function handleAuditLog(env, url) {
  const { page, pageSize, offset } = parsePagination(url)
  const { whereSql, params } = auditLogFilters(url)
  const rows = await env.DB.prepare(
    `SELECT id, admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at FROM admin_audit_log ${whereSql} ORDER BY created_at DESC LIMIT ? OFFSET ?`,
  ).bind(...params, pageSize, offset).all()
  const totalRow = await env.DB.prepare(
    `SELECT COUNT(*) AS c FROM admin_audit_log ${whereSql}`,
  ).bind(...params).first()
  return { page, pageSize, total: totalRow ? totalRow.c : 0, entries: rows.results || [] }
}

const EXPORT_MAX_ROWS = 10000

function csvCell(value) {
  if (value === null || value === undefined) return ''
  const text = String(value)
  if (text.includes(',') || text.includes('"') || text.includes('\n') || text.includes('\r')) return `"${text.replaceAll('"', '""')}"`
  return text
}

async function handleAuditExportRequest(request, env, origin) {
  const ip = request.headers.get('CF-Connecting-IP') || ''
  const ipHash = await sha256Hex(ip)
  try {
    const allowed = await checkReadRate(env.DB, 'audit-export', ipHash, Date.now())
    if (!allowed) return errorResponse(origin, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
  const { auth, error } = await authenticate(request, env, origin)
  if (error) {
    try {
      await audit(env.DB, '', 'admin_access_denied', 'api', 'audit-export', '', false)
    } catch {
    }
    return error
  }
  try {
    const url = new URL(request.url)
    const { whereSql, params } = auditLogFilters(url)
    const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS c FROM admin_audit_log ${whereSql}`).bind(...params).first()
    const total = totalRow ? totalRow.c : 0
    const rows = await env.DB.prepare(`SELECT id, admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at FROM admin_audit_log ${whereSql} ORDER BY created_at DESC LIMIT ?`).bind(...params, EXPORT_MAX_ROWS).all()
    const entries = rows.results || []
    const header = 'id,admin_user_id,action,resource_type,resource_id,reason,success,correlation_id,created_at'
    const lines = entries.map((e) => [e.id, e.admin_user_id, e.action, e.resource_type, e.resource_id, e.reason, e.success, e.correlation_id, e.created_at].map(csvCell).join(','))
    const csv = `${header}\n${lines.join('\n')}\n`
    const filterSummary = [url.searchParams.get('admin'), url.searchParams.get('action'), url.searchParams.get('resource'), url.searchParams.get('outcome')].filter(Boolean).join(',')
    await audit(env.DB, auth.userId, 'audit_exported', 'audit_log', '', `Exported ${entries.length} rows${filterSummary ? ` (filters: ${filterSummary})` : ''}`, true)
    return new Response(csv, {
      status: 200,
      headers: {
        'Content-Type': 'text/csv; charset=utf-8',
        'Content-Disposition': 'attachment; filename="kluzar-admin-audit-log.csv"',
        'X-Total-Count': String(total),
        'X-Export-Truncated': total > entries.length ? 'true' : 'false',
        ...securityHeaders(),
        ...corsHeaders(origin),
      },
    })
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
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

async function checkMutationRate(db, ipHash, nowMs) {
  const windowStart = Math.floor(nowMs / (10 * 60 * 1000))
  await db
    .prepare('INSERT INTO rate_limits (key, window_start, count, updated_at) VALUES (?, ?, 1, ?) ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1, updated_at = excluded.updated_at')
    .bind(`admin-mutation:ip:${ipHash}`, windowStart, new Date(nowMs).toISOString())
    .run()
  const row = await db
    .prepare('SELECT count FROM rate_limits WHERE key = ? AND window_start = ?')
    .bind(`admin-mutation:ip:${ipHash}`, windowStart)
    .first()
  return !!row && row.count <= 20
}

async function handleMutation(request, env, origin, endpoint, handler) {
  const ip = request.headers.get('CF-Connecting-IP') || ''
  const ipHash = await sha256Hex(ip)
  try {
    const allowed = await checkMutationRate(env.DB, ipHash, Date.now())
    if (!allowed) return errorResponse(origin, 429, 'Too many attempts. Please try again later.', 'RATE_LIMITED')
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
  const { auth, error } = await authenticate(request, env, origin)
  if (error) {
    try {
      await audit(env.DB, '', 'admin_access_denied', 'api', endpoint, '', false)
    } catch {
    }
    return error
  }
  let body = null
  try {
    body = await request.json()
  } catch {
    body = null
  }
  if (!body || typeof body !== 'object') return errorResponse(origin, 400, 'Invalid request.', 'INVALID_BODY')
  try {
    const result = await handler(env, auth, body)
    if (result === null) return errorResponse(origin, 404, 'Not found.', 'NOT_FOUND')
    if (result.error) return errorResponse(origin, result.status || 400, result.message, result.code || 'INVALID')
    return jsonResponse(origin, 200, { ok: true, ...result.data })
  } catch {
    return errorResponse(origin, 500, 'Service is not available right now.', 'UNAVAILABLE')
  }
}

async function handleEntitlementUpdate(env, auth, userId, body) {
  const plans = ['free', 'growth', 'max']
  const statuses = ['active', 'cancelled']
  const plan = typeof body.plan === 'string' ? body.plan : null
  const status = typeof body.status === 'string' ? body.status : null
  const reason = typeof body.reason === 'string' ? body.reason.trim() : ''
  if (plan !== null && !plans.includes(plan)) return { error: true, status: 400, message: 'Invalid plan.', code: 'INVALID_PLAN' }
  if (status !== null && !statuses.includes(status)) return { error: true, status: 400, message: 'Invalid status.', code: 'INVALID_STATUS' }
  if (plan === null && status === null) return { error: true, status: 400, message: 'Choose a plan or a status to change.', code: 'NO_CHANGE_FIELD' }
  if (reason.length < 10 || reason.length > 500) return { error: true, status: 400, message: 'A reason between 10 and 500 characters is required.', code: 'INVALID_REASON' }
  const current = await env.DB.prepare('SELECT plan, status FROM entitlements WHERE user_id = ?').bind(userId).first()
  if (!current) return null
  const prevPlan = current.plan
  const prevStatus = current.status
  const nextPlan = plan === null ? prevPlan : plan
  const nextStatus = status === null ? prevStatus : status
  if (nextPlan === prevPlan && nextStatus === prevStatus) return { error: true, status: 400, message: 'No change from the current subscription.', code: 'NO_CHANGE' }
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  await env.DB.batch([
    env.DB.prepare('UPDATE entitlements SET plan = ?, status = ?, updated_at = ? WHERE user_id = ?').bind(nextPlan, nextStatus, nowIso, userId),
    env.DB.prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(auth.userId, 'entitlement_corrected', 'entitlement', userId, reason, 1, correlationId, nowIso),
  ])
  return { data: { userId, plan: nextPlan, status: nextStatus, previousPlan: prevPlan, previousStatus: prevStatus } }
}

function reasonError(body) {
  const reason = typeof body.reason === 'string' ? body.reason.trim() : ''
  if (reason.length < 10 || reason.length > 500) return { error: true, status: 400, message: 'A reason between 10 and 500 characters is required.', code: 'INVALID_REASON' }
  return null
}

async function handleCompanyDetail(env, companyId) {
  const company = await env.DB.prepare('SELECT id, name, owner_user_id, created_at, updated_at FROM companies WHERE id = ?').bind(companyId).first()
  if (!company) return null
  const members = await env.DB.prepare('SELECT m.user_id, m.role, m.status, m.department_id, m.joined_at, u.email FROM company_members m LEFT JOIN users u ON u.id = m.user_id WHERE m.company_id = ? ORDER BY m.joined_at ASC').bind(companyId).all()
  return { company, members: members.results || [] }
}

async function loadActiveMember(env, companyId, userId) {
  const company = await env.DB.prepare('SELECT id, owner_user_id FROM companies WHERE id = ?').bind(companyId).first()
  if (!company) return { company: null, member: null }
  const member = await env.DB.prepare("SELECT user_id, role, status FROM company_members WHERE company_id = ? AND user_id = ? AND status = 'active'").bind(companyId, userId).first()
  return { company, member }
}

async function handleMemberRole(env, auth, companyId, userId, body) {
  const roles = ['admin', 'manager', 'employee']
  const role = typeof body.role === 'string' ? body.role : null
  if (role === null || !roles.includes(role)) return { error: true, status: 400, message: 'Invalid role.', code: 'INVALID_ROLE' }
  const badReason = reasonError(body)
  if (badReason) return badReason
  const { company, member } = await loadActiveMember(env, companyId, userId)
  if (!company) return null
  if (!member) return { error: true, status: 404, message: 'Member not found.', code: 'NOT_FOUND' }
  if (company.owner_user_id === userId) return { error: true, status: 400, message: 'The company owner cannot be changed here.', code: 'OWNER_PROTECTED' }
  if (member.role === role) return { error: true, status: 400, message: 'No change from the current role.', code: 'NO_CHANGE' }
  const prevRole = member.role
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  await env.DB.batch([
    env.DB.prepare('UPDATE company_members SET role = ? WHERE company_id = ? AND user_id = ?').bind(role, companyId, userId),
    env.DB.prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(auth.userId, 'member_role_changed', 'company_member', userId, body.reason.trim(), 1, correlationId, nowIso),
  ])
  return { data: { companyId, userId, role, previousRole: prevRole } }
}

async function handleMemberRemove(env, auth, companyId, userId, body) {
  const badReason = reasonError(body)
  if (badReason) return badReason
  const { company, member } = await loadActiveMember(env, companyId, userId)
  if (!company) return null
  if (!member) return { error: true, status: 404, message: 'Member not found.', code: 'NOT_FOUND' }
  if (company.owner_user_id === userId) return { error: true, status: 400, message: 'The company owner cannot be removed here.', code: 'OWNER_PROTECTED' }
  if (member.role === 'owner') {
    const owners = await env.DB.prepare("SELECT COUNT(*) AS c FROM company_members WHERE company_id = ? AND role = 'owner' AND status = 'active'").bind(companyId).first()
    if (!owners || owners.c <= 1) return { error: true, status: 400, message: 'The last owner-role member cannot be removed.', code: 'LAST_OWNER' }
  }
  const prevRole = member.role
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  await env.DB.batch([
    env.DB.prepare("UPDATE company_members SET status = 'removed' WHERE company_id = ? AND user_id = ?").bind(companyId, userId),
    env.DB.prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(auth.userId, 'member_removed', 'company_member', userId, body.reason.trim(), 1, correlationId, nowIso),
  ])
  return { data: { companyId, userId, status: 'removed', previousRole: prevRole } }
}

function randomHexBytes(count) {
  const bytes = new Uint8Array(count)
  crypto.getRandomValues(bytes)
  return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('')
}

function b64encodeBytes(bytes) {
  let text = ''
  for (const b of bytes) text += String.fromCharCode(b)
  return btoa(text)
}

async function hashTempPassword(password) {
  const salt = new Uint8Array(16)
  crypto.getRandomValues(salt)
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, key, 256)
  return `pbkdf2-sha256$100000$${b64encodeBytes(salt)}$${b64encodeBytes(new Uint8Array(bits))}`
}

function generateTempPassword() {
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
  const lower = 'abcdefghijklmnopqrstuvwxyz'
  const digits = '0123456789'
  const symbols = '!@#$%^&*'
  const all = upper + lower + digits + symbols
  const pick = (set) => set[crypto.getRandomValues(new Uint32Array(1))[0] % set.length]
  const chars = [pick(upper), pick(lower), pick(digits), pick(symbols)]
  for (let i = 0; i < 16; i++) chars.push(pick(all))
  for (let i = chars.length - 1; i > 0; i--) {
    const j = crypto.getRandomValues(new Uint32Array(1))[0] % (i + 1)
    const tmp = chars[i]
    chars[i] = chars[j]
    chars[j] = tmp
  }
  return chars.join('')
}

function normalizeAdminEmail(email) {
  return String(email || '').trim().toLowerCase()
}

function validAdminEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/.test(email.trim()) && email.length <= 254
}

async function handleUserCreate(env, auth, body) {
  const email = typeof body.email === 'string' ? normalizeAdminEmail(body.email) : ''
  const firstName = typeof body.firstName === 'string' ? body.firstName.trim() : ''
  const lastName = typeof body.lastName === 'string' ? body.lastName.trim() : ''
  const phone = typeof body.phone === 'string' ? body.phone.trim() : ''
  const plan = typeof body.plan === 'string' ? body.plan : 'free'
  const badReason = reasonError(body)
  if (badReason) return badReason
  if (!validAdminEmail(email)) return { error: true, status: 400, message: 'Enter a valid email.', code: 'INVALID_EMAIL' }
  if (!['free', 'growth', 'max'].includes(plan)) return { error: true, status: 400, message: 'Invalid plan.', code: 'INVALID_PLAN' }
  if (firstName.length > 100 || lastName.length > 100 || phone.length > 30) return { error: true, status: 400, message: 'Name or phone is too long.', code: 'INVALID_FIELD' }
  const existing = await env.DB.prepare('SELECT id FROM users WHERE email_normalized = ?').bind(email).first()
  if (existing) return { error: true, status: 409, message: 'A user with this email already exists.', code: 'USER_EXISTS' }
  const userId = randomHexBytes(16)
  const tempPassword = generateTempPassword()
  const passwordHash = await hashTempPassword(tempPassword)
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  await env.DB.batch([
    env.DB.prepare('INSERT INTO users (id, email, email_normalized, password_hash, status, email_verified, mfa_enabled, first_name, last_name, phone, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').bind(userId, email, email, passwordHash, 'pending_mfa', 0, 0, firstName, lastName, phone, nowIso, nowIso),
    env.DB.prepare('INSERT INTO entitlements (user_id, plan, status, updated_at) VALUES (?, ?, ?, ?)').bind(userId, plan, 'active', nowIso),
    env.DB.prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(auth.userId, 'user_created', 'user', userId, body.reason.trim(), 1, correlationId, nowIso),
  ])
  return { data: { userId, email, plan, tempPassword } }
}

async function handleUserDeactivate(env, auth, userId, body) {
  const badReason = reasonError(body)
  if (badReason) return badReason
  if (auth.userId === userId) return { error: true, status: 403, message: 'You cannot deactivate your own account.', code: 'SELF_PROTECTED' }
  const user = await env.DB.prepare('SELECT status FROM users WHERE id = ?').bind(userId).first()
  if (!user) return null
  if (user.status === 'suspended') return { error: true, status: 400, message: 'This account is already suspended.', code: 'ALREADY_SUSPENDED' }
  const prevStatus = user.status
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  await env.DB.batch([
    env.DB.prepare("UPDATE users SET status = 'suspended', updated_at = ? WHERE id = ?").bind(nowIso, userId),
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(userId),
    env.DB.prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(auth.userId, 'user_deactivated', 'user', userId, body.reason.trim(), 1, correlationId, nowIso),
  ])
  return { data: { userId, status: 'suspended', previousStatus: prevStatus } }
}

async function handleUserReactivate(env, auth, userId, body) {
  const badReason = reasonError(body)
  if (badReason) return badReason
  const user = await env.DB.prepare('SELECT status, mfa_enabled FROM users WHERE id = ?').bind(userId).first()
  if (!user) return null
  if (user.status !== 'suspended') return { error: true, status: 400, message: 'This account is not suspended.', code: 'NOT_SUSPENDED' }
  const nextStatus = user.mfa_enabled === 1 ? 'active' : 'pending_mfa'
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  await env.DB.batch([
    env.DB.prepare('UPDATE users SET status = ?, updated_at = ? WHERE id = ?').bind(nextStatus, nowIso, userId),
    env.DB.prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(auth.userId, 'user_reactivated', 'user', userId, body.reason.trim(), 1, correlationId, nowIso),
  ])
  return { data: { userId, status: nextStatus, previousStatus: 'suspended' } }
}

async function handleMemberAdd(env, auth, companyId, body) {
  const email = typeof body.email === 'string' ? normalizeAdminEmail(body.email) : ''
  const roles = ['admin', 'manager', 'employee']
  const role = typeof body.role === 'string' ? body.role : null
  const badReason = reasonError(body)
  if (badReason) return badReason
  if (!validAdminEmail(email)) return { error: true, status: 400, message: 'Enter a valid email.', code: 'INVALID_EMAIL' }
  if (role === null || !roles.includes(role)) return { error: true, status: 400, message: 'Invalid role.', code: 'INVALID_ROLE' }
  const company = await env.DB.prepare('SELECT id, owner_user_id FROM companies WHERE id = ?').bind(companyId).first()
  if (!company) return null
  const user = await env.DB.prepare('SELECT id, status FROM users WHERE email_normalized = ?').bind(email).first()
  if (!user) return { error: true, status: 404, message: 'No account with this email. Create the user first.', code: 'USER_NOT_FOUND' }
  if (company.owner_user_id === user.id) return { error: true, status: 400, message: 'The company owner is already the owner.', code: 'OWNER_PROTECTED' }
  if (user.status === 'suspended') return { error: true, status: 400, message: 'This account is suspended.', code: 'USER_SUSPENDED' }
  const existing = await env.DB.prepare('SELECT status FROM company_members WHERE company_id = ? AND user_id = ?').bind(companyId, user.id).first()
  if (existing && existing.status === 'active') return { error: true, status: 400, message: 'This user is already a member.', code: 'ALREADY_MEMBER' }
  const nowIso = new Date().toISOString()
  const correlationId = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`
  const ops = []
  if (existing) {
    ops.push(env.DB.prepare('UPDATE company_members SET role = ?, status = ?, joined_at = ? WHERE company_id = ? AND user_id = ?').bind(role, 'active', nowIso, companyId, user.id))
  } else {
    ops.push(env.DB.prepare('INSERT INTO company_members (company_id, user_id, role, department_id, status, invited_by, joined_at) VALUES (?, ?, ?, NULL, ?, ?, ?)').bind(companyId, user.id, role, 'active', auth.userId, nowIso))
  }
  ops.push(env.DB.prepare('INSERT INTO admin_audit_log (admin_user_id, action, resource_type, resource_id, reason, success, correlation_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').bind(auth.userId, 'member_added', 'company_member', user.id, body.reason.trim(), 1, correlationId, nowIso))
  await env.DB.batch(ops)
  return { data: { companyId, userId: user.id, email, role, status: 'active' } }
}

async function handlePayments(env, url) {
  const { page, pageSize, offset } = parsePagination(url)
  const plan = url.searchParams.get('plan') || ''
  const status = url.searchParams.get('status') || ''
  const where = []
  const params = []
  if (plan) {
    where.push('e.plan = ?')
    params.push(plan)
  }
  if (status) {
    where.push('e.status = ?')
    params.push(status)
  }
  const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : ''
  const totalRow = await env.DB.prepare(`SELECT COUNT(*) AS total FROM entitlements e ${whereSql}`).bind(...params).first()
  const rows = await env.DB.prepare(`SELECT e.user_id, u.email, e.plan, e.status, e.provider, e.provider_subscription_id, e.current_period_end, e.updated_at FROM entitlements e LEFT JOIN users u ON u.id = e.user_id ${whereSql} ORDER BY e.updated_at DESC LIMIT ? OFFSET ?`).bind(...params, pageSize, offset).all()
  return { payments: rows.results || [], total: totalRow ? totalRow.total : 0, page, pageSize }
}

const SERVICE_HEALTH_URLS = [
  { service: 'seo-api', url: 'https://seo-api.kluzar.com/api/health' },
  { service: 'manage-api', url: 'https://manage-api.kluzar.com/api/health' },
  { service: 'business-api', url: 'https://business-api.kluzar.com/api/health' },
  { service: 'dashboard-api', url: 'https://dashboard-api.kluzar.com/api/health' },
]

async function probeService(entry) {
  const started = Date.now()
  try {
    const res = await fetch(entry.url, { signal: AbortSignal.timeout(5000) })
    return { service: entry.service, url: entry.url, ok: res.ok, status: res.status, ms: Date.now() - started }
  } catch {
    return { service: entry.service, url: entry.url, ok: false, status: null, ms: Date.now() - started }
  }
}

async function handleServices() {
  const probed = await Promise.all(SERVICE_HEALTH_URLS.map((entry) => probeService(entry)))
  const services = [
    { service: 'account-api', url: 'https://account-api.kluzar.com', ok: null, status: null, ms: null, note: 'No public health endpoint' },
    { service: 'admin-api', url: 'https://admin-api.kluzar.com', ok: true, status: 200, ms: 0, note: 'This service' },
    ...probed,
  ]
  return { services, checkedAt: new Date().toISOString() }
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
    if (method === 'GET' && path === '/api/payments') {
      return handleRead(request, env, origin, 'payments', async (dbEnv) => handlePayments(dbEnv, url))
    }
    if (method === 'GET' && path === '/api/services') {
      return handleRead(request, env, origin, 'services', async () => handleServices())
    }
    if (method === 'GET' && path === '/api/audit-log/export') {
      return handleAuditExportRequest(request, env, origin)
    }
    if (method === 'GET' && path.startsWith('/api/companies/')) {
      const companyId = decodeURIComponent(path.slice('/api/companies/'.length))
      if (!companyId || companyId.length > 128 || companyId.includes('/')) return errorResponse(origin, 400, 'Invalid company id.', 'INVALID_ID')
      return handleRead(request, env, origin, 'company-detail', async (dbEnv) => handleCompanyDetail(dbEnv, companyId))
    }
    if (method === 'POST' && path.startsWith('/api/companies/') && path.endsWith('/role')) {
      const rest = path.slice('/api/companies/'.length, -'/role'.length)
      const parts = rest.split('/')
      if (parts.length !== 3 || parts[1] !== 'members' || !parts[0] || !parts[2] || parts[0].length > 128 || parts[2].length > 128) return errorResponse(origin, 400, 'Invalid member id.', 'INVALID_ID')
      const companyId = decodeURIComponent(parts[0])
      const userId = decodeURIComponent(parts[2])
      return handleMutation(request, env, origin, 'member-role', async (dbEnv, auth, body) => handleMemberRole(dbEnv, auth, companyId, userId, body))
    }
    if (method === 'POST' && path.startsWith('/api/companies/') && path.endsWith('/remove')) {
      const rest = path.slice('/api/companies/'.length, -'/remove'.length)
      const parts = rest.split('/')
      if (parts.length !== 3 || parts[1] !== 'members' || !parts[0] || !parts[2] || parts[0].length > 128 || parts[2].length > 128) return errorResponse(origin, 400, 'Invalid member id.', 'INVALID_ID')
      const companyId = decodeURIComponent(parts[0])
      const userId = decodeURIComponent(parts[2])
      return handleMutation(request, env, origin, 'member-remove', async (dbEnv, auth, body) => handleMemberRemove(dbEnv, auth, companyId, userId, body))
    }
    if (method === 'POST' && path.startsWith('/api/users/') && path.endsWith('/entitlement')) {
      const userId = decodeURIComponent(path.slice('/api/users/'.length, -'/entitlement'.length))
      if (!userId || userId.length > 128 || userId.includes('/')) return errorResponse(origin, 400, 'Invalid user id.', 'INVALID_ID')
      return handleMutation(request, env, origin, 'entitlement-update', async (dbEnv, auth, body) => handleEntitlementUpdate(dbEnv, auth, userId, body))
    }
    if (method === 'POST' && path === '/api/users') {
      return handleMutation(request, env, origin, 'user-create', async (dbEnv, auth, body) => handleUserCreate(dbEnv, auth, body))
    }
    if (method === 'POST' && path.startsWith('/api/users/') && path.endsWith('/deactivate')) {
      const userId = decodeURIComponent(path.slice('/api/users/'.length, -'/deactivate'.length))
      if (!userId || userId.length > 128 || userId.includes('/')) return errorResponse(origin, 400, 'Invalid user id.', 'INVALID_ID')
      return handleMutation(request, env, origin, 'user-deactivate', async (dbEnv, auth, body) => handleUserDeactivate(dbEnv, auth, userId, body))
    }
    if (method === 'POST' && path.startsWith('/api/users/') && path.endsWith('/reactivate')) {
      const userId = decodeURIComponent(path.slice('/api/users/'.length, -'/reactivate'.length))
      if (!userId || userId.length > 128 || userId.includes('/')) return errorResponse(origin, 400, 'Invalid user id.', 'INVALID_ID')
      return handleMutation(request, env, origin, 'user-reactivate', async (dbEnv, auth, body) => handleUserReactivate(dbEnv, auth, userId, body))
    }
    if (method === 'POST' && path.startsWith('/api/companies/') && path.endsWith('/members')) {
      const companyId = decodeURIComponent(path.slice('/api/companies/'.length, -'/members'.length))
      if (!companyId || companyId.length > 128 || companyId.includes('/')) return errorResponse(origin, 400, 'Invalid company id.', 'INVALID_ID')
      return handleMutation(request, env, origin, 'member-add', async (dbEnv, auth, body) => handleMemberAdd(dbEnv, auth, companyId, body))
    }
    if (path === '/api/health' || path === '/api/auth/verify' || path === '/api/overview' || path === '/api/users' || path.startsWith('/api/users/') || path === '/api/companies' || path.startsWith('/api/companies/') || path === '/api/payments' || path === '/api/services' || path === '/api/audit-log' || path === '/api/audit-log/export') {
      return errorResponse(origin, 405, 'Method not allowed.', 'METHOD_NOT_ALLOWED')
    }
    return errorResponse(origin, 404, 'Not found.', 'NOT_FOUND')
  },
}
