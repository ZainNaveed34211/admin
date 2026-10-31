import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

const USERS = [
  { id: 'user-1', email: 'one@example.test', first_name: 'One', last_name: 'User', phone: null, status: 'active', email_verified: 1, mfa_enabled: 1, created_at: '2026-10-01T00:00:00.000Z', updated_at: '2026-10-01T00:00:00.000Z' },
  { id: 'user-2', email: 'two@example.test', first_name: 'Two', last_name: 'User', phone: null, status: 'active', email_verified: 1, mfa_enabled: 0, created_at: '2026-10-02T00:00:00.000Z', updated_at: '2026-10-02T00:00:00.000Z' },
]

function filterUsers(params) {
  const q = params[0]
  const like = String(params[1] || '').replaceAll('%', '').toLowerCase()
  return USERS.filter((u) => u.id === q || u.email.toLowerCase().includes(like) || `${u.first_name} ${u.last_name}`.toLowerCase().includes(like))
}

function makeDb({ scope = 'admin', userStatus = 'active', sessionExpiry = NOW + 3600 * 1000, allowlisted = true, sessionExists = true } = {}) {
  const rateCounts = new Map()
  const audits = []
  const entitlement = { plan: 'free', status: 'active', provider: 'manual', provider_subscription_id: 'sub-1' }
  const bound = (sql, params) => ({
    sql,
    params,
    async first() {
      if (sql.includes('FROM sessions') && sql.includes('WHERE s.id')) {
        if (!sessionExists) return null
        return { id: 'sess-1', user_id: 'user-1', expires_at: new Date(sessionExpiry).toISOString(), scope, user_status: userStatus, user_email: 'admin@example.test' }
      }
      if (sql.includes('FROM admin_allowlist')) return allowlisted ? { user_id: 'user-1' } : null
      if (sql.includes('SELECT count FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
      if (sql.includes('FROM users u') && sql.includes('u.id = ?')) return { c: filterUsers(params).length }
      if (sql.includes('COUNT(*) AS c')) return { c: 1 }
      if (sql.includes('FROM entitlements') && sql.includes('user_id = ?')) return entitlement
      if (sql.includes('FROM companies WHERE id')) return params[0] === 'co-1' ? { id: 'co-1', owner_user_id: 'owner-1', name: 'Co', created_at: '2026-10-01T00:00:00.000Z', updated_at: '2026-10-01T00:00:00.000Z' } : null
      if (sql.includes('FROM company_members') && sql.includes("status = 'active'") && sql.includes('user_id = ?')) {
        if (params[0] === 'co-1' && params[1] === 'user-2') return { user_id: 'user-2', role: 'manager', status: 'active' }
        return null
      }
      if (sql.includes('COUNT(*)') && sql.includes("role = 'owner'")) return { c: 2 }
      if (sql.includes('FROM users u') && sql.includes('WHERE u.id = ?')) {
        const row = USERS.find((u) => u.id === params[0])
        if (!row) return null
        return { ...row, plan: 'free', plan_status: 'active', provider: null, provider_subscription_id: null, current_period_end: null, entitlement_updated_at: row.updated_at }
      }
      return null
    },
    async all() {
      if (sql.includes('FROM users u') && sql.includes('LEFT JOIN entitlements')) {
        let rows = USERS
        if (sql.includes('u.id = ?')) {
          rows = filterUsers(params)
        }
        const limit = params[params.length - 2]
        const offset = params[params.length - 1]
        return { results: rows.slice(offset, offset + limit).map((u) => ({ ...u, plan: 'free', plan_status: 'active', current_period_end: null })) }
      }
      if (sql.includes('GROUP BY status')) return { results: [{ status: 'active', c: 2 }] }
      if (sql.includes('GROUP BY plan')) return { results: [{ plan: 'free', c: 2 }] }
      if (sql.includes('FROM company_members m LEFT JOIN')) return { results: [] }
      if (sql.includes('FROM admin_audit_log')) return { results: [] }
      if (sql.includes('FROM entitlements e LEFT JOIN')) return { results: [] }
      return { results: [] }
    },
    async run() {
      if (sql.includes('INTO rate_limits')) {
        rateCounts.set(params[0], (rateCounts.get(params[0]) || 0) + 1)
      }
      if (sql.includes('INTO admin_audit_log')) {
        audits.push({ action: params[1] })
      }
      return { meta: { changes: 1 } }
    },
  })
  return {
    audits,
    entitlement,
    prepare(sql) {
      return {
        bind: (...params) => bound(sql, params),
        first: () => bound(sql, []).first(),
        all: () => bound(sql, []).all(),
        run: () => bound(sql, []).run(),
      }
    },
    async batch(statements) {
      const results = []
      for (const st of statements) {
        if (st.sql.includes('UPDATE entitlements')) entitlement.plan = st.params[0]
        if (st.sql.includes('INTO admin_audit_log')) audits.push({ action: st.params[1] })
        results.push({ meta: { changes: 1 } })
      }
      return results
    },
  }
}

async function keypair() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
  return { pub, priv }
}

async function token(priv, claims = {}) {
  const nowSec = Math.floor(NOW / 1000)
  return signAssertionForTest(priv, { sub: 'user-1', sid: 'sess-1', aud: 'kluzar-admin-api', iat: nowSec, exp: nowSec + 300, jti: 'jti-1', mfa: true, ...claims }, claims.kid || 'admin-assertion-v1')
}

function call(env, path, { origin = ADMIN_ORIGIN, tok = null, method = 'GET', body = null } = {}) {
  const headers = {}
  if (origin) headers.Origin = origin
  if (tok) headers.Authorization = `Bearer ${tok}`
  if (body !== null) headers['Content-Type'] = 'application/json'
  return worker.fetch(new Request(`https://admin-api.kluzar.com${path}`, { method, headers, body: body !== null ? JSON.stringify(body) : undefined }), env)
}

const ENDPOINTS = [
  { method: 'GET', path: '/api/overview' },
  { method: 'GET', path: '/api/users' },
  { method: 'GET', path: '/api/users/user-1' },
  { method: 'GET', path: '/api/companies' },
  { method: 'GET', path: '/api/companies/co-1' },
  { method: 'GET', path: '/api/payments' },
  { method: 'GET', path: '/api/audit-log' },
  { method: 'GET', path: '/api/audit-log/export' },
  { method: 'POST', path: '/api/users/user-1/entitlement', body: { plan: 'growth', reason: 'A long enough reason here' } },
  { method: 'POST', path: '/api/companies/co-1/members/user-2/role', body: { role: 'admin', reason: 'A long enough reason here' } },
  { method: 'POST', path: '/api/companies/co-1/members/user-2/remove', body: { reason: 'A long enough reason here' } },
]

test('auth matrix: every protected endpoint rejects no-token, wrong-origin, non-allowlisted, and full-scope sessions', async () => {
  const { pub, priv } = await keypair()
  const good = await token(priv)
  for (const ep of ENDPOINTS) {
    const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
    const noAuth = await call(env, ep.path, { method: ep.method, body: ep.body || null })
    assert.equal(noAuth.status, 401, `${ep.method} ${ep.path} without token`)
    const wrongOrigin = await call(env, ep.path, { tok: good, origin: 'https://evil.test', method: ep.method, body: ep.body || null })
    assert.equal(wrongOrigin.status, 403, `${ep.method} ${ep.path} wrong origin`)
    const envNoAllow = { DB: makeDb({ allowlisted: false }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
    const noAllow = await call(envNoAllow, ep.path, { tok: good, method: ep.method, body: ep.body || null })
    assert.equal(noAllow.status, 403, `${ep.method} ${ep.path} non-allowlisted`)
    const envFull = { DB: makeDb({ scope: 'full' }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
    const fullScope = await call(envFull, ep.path, { tok: good, method: ep.method, body: ep.body || null })
    assert.equal(fullScope.status, 403, `${ep.method} ${ep.path} full-scope session`)
  }
})

test('assertion variants: expired, tampered, wrong audience, dead session, inactive account all rejected', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const expired = await call(env, '/api/overview', { tok: await token(priv, { iat: Math.floor(NOW / 1000) - 900, exp: Math.floor(NOW / 1000) - 600 }) })
  assert.equal(expired.status, 401)
  const good = await token(priv)
  const tampered = good.slice(0, -1) + (good.slice(-1) === 'A' ? 'B' : 'A')
  const tamperedRes = await call(env, '/api/overview', { tok: tampered })
  assert.equal(tamperedRes.status, 401)
  const wrongAud = await call(env, '/api/overview', { tok: await token(priv, { aud: 'kluzar-manage-api' }) })
  assert.equal(wrongAud.status, 401)
  const noMfa = await call(env, '/api/overview', { tok: await token(priv, { mfa: false }) })
  assert.equal(noMfa.status, 403)
  const envDead = { DB: makeDb({ sessionExists: false }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const dead = await call(envDead, '/api/overview', { tok: good })
  assert.equal(dead.status, 401)
  const envInactive = { DB: makeDb({ userStatus: 'suspended' }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const inactive = await call(envInactive, '/api/overview', { tok: good })
  assert.equal(inactive.status, 401)
})

test('rate limits: verify endpoint and read endpoints trip after their budgets', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  let last = null
  for (let i = 0; i < 21; i++) {
    last = await call(env, '/api/auth/verify', { tok, method: 'POST' })
  }
  assert.equal(last.status, 429)
  const envReads = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  for (let i = 0; i < 61; i++) {
    last = await call(envReads, '/api/overview', { tok })
  }
  assert.equal(last.status, 429)
})

test('no secret columns are selected or returned anywhere', async () => {
  const dir = path.dirname(fileURLToPath(import.meta.url))
  const source = fs.readFileSync(path.join(dir, '..', 'worker', 'src', 'index.js'), 'utf8')
  assert.ok(!/SELECT[^;]*(password_hash|token_hash|csrf_token|ip_hash)/.test(source), 'a SELECT names a secret column')
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const res = await call(env, '/api/users/user-1', { tok: await token(priv) })
  assert.equal(res.status, 200)
  const body = await res.text()
  for (const secret of ['password_hash', 'token_hash', 'csrf_token', 'ip_hash']) {
    assert.ok(!body.includes(secret), `response leaks ${secret}`)
  }
})

test('injection attempts fail safely and method guards hold', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const injected = await call(env, "/api/users?q=' OR '1'='1", { tok })
  assert.equal(injected.status, 200)
  const injectedData = await injected.json()
  assert.equal(injectedData.total, 0)
  const dropAttempt = await call(env, '/api/users/user-1/entitlement', { tok, method: 'POST', body: { plan: 'growth', reason: "x'); DROP TABLE users; -- ok fine here" } })
  assert.equal(dropAttempt.status, 200)
  const stillAlive = await call(env, '/api/overview', { tok })
  assert.equal(stillAlive.status, 200)
  for (const path of ['/api/overview', '/api/users', '/api/audit-log/export']) {
    for (const method of ['PUT', 'DELETE']) {
      const res = await call(env, path, { tok, method })
      assert.equal(res.status, 405, `${method} ${path}`)
    }
  }
})
