import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()
const REASON = 'Phase 9 test reason for this change'

function makeDb(seed = {}) {
  const users = new Map()
  const entitlements = new Map()
  const members = new Map()
  const companies = new Map()
  const sessions = []
  const audits = []
  const rateCounts = new Map()
  users.set('user-1', { id: 'user-1', email: 'admin@example.test', email_normalized: 'admin@example.test', password_hash: 'x', status: 'active', email_verified: 1, mfa_enabled: 1, first_name: 'Admin', last_name: '', phone: '', created_at: '2026-10-01T00:00:00.000Z', updated_at: '2026-10-01T00:00:00.000Z' })
  if (seed.users) for (const u of seed.users) users.set(u.id, { ...u })
  if (seed.companies) for (const c of seed.companies) companies.set(c.id, { ...c })
  if (seed.members) for (const m of seed.members) members.set(`${m.company_id}|${m.user_id}`, { ...m })
  if (seed.sessions) sessions.push(...seed.sessions)
  const sessionRow = seed.sessionRow !== undefined ? seed.sessionRow : { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
  const allowlisted = seed.allowlisted !== false

  function apply(sql, params) {
    if (sql.includes('INTO rate_limits')) {
      rateCounts.set(params[0], (rateCounts.get(params[0]) || 0) + 1)
      return { meta: { changes: 1 } }
    }
    if (sql.includes('INSERT INTO users')) {
      users.set(params[0], { id: params[0], email: params[1], email_normalized: params[2], password_hash: params[3], status: params[4], email_verified: params[5], mfa_enabled: params[6], first_name: params[7], last_name: params[8], phone: params[9], created_at: params[10], updated_at: params[11] })
      return { meta: { changes: 1 } }
    }
    if (sql.includes('INSERT INTO entitlements')) {
      entitlements.set(params[0], { user_id: params[0], plan: params[1], status: params[2], updated_at: params[3] })
      return { meta: { changes: 1 } }
    }
    if (sql.includes('INSERT INTO company_members')) {
      members.set(`${params[0]}|${params[1]}`, { company_id: params[0], user_id: params[1], role: params[2], department_id: null, status: params[3], invited_by: params[4], joined_at: params[5] })
      return { meta: { changes: 1 } }
    }
    if (sql.includes('UPDATE users SET')) {
      const row = users.get(params[params.length - 1])
      if (row) {
        row.status = sql.includes("'suspended'") ? 'suspended' : params[0]
        row.updated_at = sql.includes("'suspended'") ? params[0] : params[1]
      }
      return { meta: { changes: 1 } }
    }
    if (sql.includes('UPDATE company_members SET')) {
      const row = members.get(`${params[3]}|${params[4]}`)
      if (row) {
        row.role = params[0]
        row.status = params[1]
        row.joined_at = params[2]
      }
      return { meta: { changes: 1 } }
    }
    if (sql.includes('DELETE FROM sessions')) {
      for (let i = sessions.length - 1; i >= 0; i--) {
        if (sessions[i].user_id === params[0]) sessions.splice(i, 1)
      }
      return { meta: { changes: 1 } }
    }
    if (sql.includes('INTO admin_audit_log')) {
      audits.push({ admin_user_id: params[0], action: params[1], resource_type: params[2], resource_id: params[3], reason: params[4], success: params[5] })
      return { meta: { changes: 1 } }
    }
    return { meta: { changes: 0 } }
  }

  function select(sql, params) {
    if (sql.includes('FROM sessions') && sql.includes('WHERE s.id')) return sessionRow
    if (sql.includes('FROM admin_allowlist')) return allowlisted ? { user_id: 'user-1' } : null
    if (sql.includes('SELECT count FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
    if (sql.includes('FROM users WHERE email_normalized')) {
      for (const u of users.values()) if (u.email_normalized === params[0]) return { id: u.id, status: u.status }
      return null
    }
    if (sql.includes('FROM users WHERE id')) {
      const u = users.get(params[0])
      return u ? { status: u.status, mfa_enabled: u.mfa_enabled } : null
    }
    if (sql.includes('FROM companies WHERE id')) {
      const c = companies.get(params[0])
      return c ? { id: c.id, owner_user_id: c.owner_user_id } : null
    }
    if (sql.includes('FROM company_members WHERE company_id')) {
      return members.get(`${params[0]}|${params[1]}`) || null
    }
    return null
  }

  const bound = (sql, params) => ({
    sql,
    params,
    async first() { return select(sql, params) },
    async all() { return { results: [] } },
    async run() { return apply(sql, params) },
  })
  return {
    users,
    entitlements,
    members,
    sessions,
    audits,
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
      for (const st of statements) results.push(apply(st.sql, st.params))
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

async function setup() {
  const { pub, priv } = await keypair()
  const tok = await token(priv)
  return { pub, priv, tok }
}

const USER2 = { id: 'user-2', email: 'two@example.test', email_normalized: 'two@example.test', password_hash: 'x', status: 'active', email_verified: 1, mfa_enabled: 1, first_name: 'Two', last_name: '', phone: '', created_at: '2026-10-02T00:00:00.000Z', updated_at: '2026-10-02T00:00:00.000Z' }
const CO1 = { id: 'co-1', owner_user_id: 'user-1', name: 'Co' }

test('create user: success stores pending_mfa user, entitlement, audit, and a strong one-time password', async () => {
  const { pub, tok } = await setup()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const res = await call(env, '/api/users', { method: 'POST', tok, body: { email: 'New@Example.test', firstName: 'New', plan: 'growth', reason: REASON } })
  assert.equal(res.status, 200)
  const data = await res.json()
  assert.equal(data.ok, true)
  assert.equal(data.email, 'new@example.test')
  assert.equal(data.plan, 'growth')
  assert.match(data.tempPassword, /[a-z]/)
  assert.match(data.tempPassword, /[A-Z]/)
  assert.match(data.tempPassword, /[0-9]/)
  assert.match(data.tempPassword, /[^A-Za-z0-9]/)
  assert.ok(data.tempPassword.length >= 12)
  const row = db.users.get(data.userId)
  assert.equal(row.status, 'pending_mfa')
  assert.equal(row.mfa_enabled, 0)
  assert.match(row.password_hash, /^pbkdf2-sha256\$100000\$/)
  assert.equal(db.entitlements.get(data.userId).plan, 'growth')
  assert.equal(db.audits.filter((a) => a.action === 'user_created').length, 1)
})

test('create user: duplicate email, invalid email, invalid plan, and short reason are rejected', async () => {
  const { pub, tok } = await setup()
  const db = makeDb({ users: [USER2] })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const dup = await call(env, '/api/users', { method: 'POST', tok, body: { email: 'two@example.test', reason: REASON } })
  assert.equal(dup.status, 409)
  const badEmail = await call(env, '/api/users', { method: 'POST', tok, body: { email: 'not-an-email', reason: REASON } })
  assert.equal(badEmail.status, 400)
  const badPlan = await call(env, '/api/users', { method: 'POST', tok, body: { email: 'ok@example.test', plan: 'ultra', reason: REASON } })
  assert.equal(badPlan.status, 400)
  const badReason = await call(env, '/api/users', { method: 'POST', tok, body: { email: 'ok@example.test', reason: 'short' } })
  assert.equal(badReason.status, 400)
  assert.equal(db.users.size, 2)
})

test('create user: no token is 401 and wrong origin is 403', async () => {
  const { pub, tok } = await setup()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const noTok = await call(env, '/api/users', { method: 'POST', body: { email: 'a@example.test', reason: REASON } })
  assert.equal(noTok.status, 401)
  const wrongOrigin = await call(env, '/api/users', { method: 'POST', tok, origin: 'https://evil.example.test', body: { email: 'a@example.test', reason: REASON } })
  assert.equal(wrongOrigin.status, 403)
})

test('deactivate: success suspends, deletes sessions, and audits; self, repeat, and missing are rejected', async () => {
  const { pub, tok } = await setup()
  const db = makeDb({ users: [USER2], sessions: [{ user_id: 'user-2' }, { user_id: 'user-2' }, { user_id: 'user-1' }] })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const res = await call(env, '/api/users/user-2/deactivate', { method: 'POST', tok, body: { reason: REASON } })
  assert.equal(res.status, 200)
  const data = await res.json()
  assert.equal(data.status, 'suspended')
  assert.equal(data.previousStatus, 'active')
  assert.equal(db.users.get('user-2').status, 'suspended')
  assert.equal(db.sessions.filter((s) => s.user_id === 'user-2').length, 0)
  assert.equal(db.sessions.filter((s) => s.user_id === 'user-1').length, 1)
  assert.equal(db.audits.filter((a) => a.action === 'user_deactivated').length, 1)
  const repeat = await call(env, '/api/users/user-2/deactivate', { method: 'POST', tok, body: { reason: REASON } })
  assert.equal(repeat.status, 400)
  const self = await call(env, '/api/users/user-1/deactivate', { method: 'POST', tok, body: { reason: REASON } })
  assert.equal(self.status, 403)
  const missing = await call(env, '/api/users/nope/deactivate', { method: 'POST', tok, body: { reason: REASON } })
  assert.equal(missing.status, 404)
})

test('reactivate: suspended with MFA returns active, suspended without MFA returns pending_mfa, others are rejected', async () => {
  const { pub, tok } = await setup()
  const suspendedMfa = { ...USER2, status: 'suspended', mfa_enabled: 1 }
  const suspendedNoMfa = { id: 'user-3', email: 'three@example.test', email_normalized: 'three@example.test', password_hash: 'x', status: 'suspended', email_verified: 0, mfa_enabled: 0, first_name: '', last_name: '', phone: '', created_at: '2026-10-03T00:00:00.000Z', updated_at: '2026-10-03T00:00:00.000Z' }
  const db = makeDb({ users: [suspendedMfa, suspendedNoMfa] })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const resMfa = await call(env, '/api/users/user-2/reactivate', { method: 'POST', tok, body: { reason: REASON } })
  assert.equal(resMfa.status, 200)
  assert.equal((await resMfa.json()).status, 'active')
  const resNoMfa = await call(env, '/api/users/user-3/reactivate', { method: 'POST', tok, body: { reason: REASON } })
  assert.equal((await resNoMfa.json()).status, 'pending_mfa')
  const notSuspended = await call(env, '/api/users/user-2/reactivate', { method: 'POST', tok, body: { reason: REASON } })
  assert.equal(notSuspended.status, 400)
  assert.equal(db.audits.filter((a) => a.action === 'user_reactivated').length, 2)
})

test('add member: insert, re-add of removed member, and all guards', async () => {
  const { pub, tok } = await setup()
  const removed = { company_id: 'co-1', user_id: 'user-2', role: 'employee', department_id: null, status: 'removed', invited_by: 'owner-1', joined_at: '2026-10-02T00:00:00.000Z' }
  const suspendedUser = { id: 'user-4', email: 'four@example.test', email_normalized: 'four@example.test', password_hash: 'x', status: 'suspended', email_verified: 1, mfa_enabled: 1, first_name: '', last_name: '', phone: '', created_at: '2026-10-04T00:00:00.000Z', updated_at: '2026-10-04T00:00:00.000Z' }
  const db = makeDb({ users: [USER2, suspendedUser], companies: [CO1], members: [removed] })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const reAdd = await call(env, '/api/companies/co-1/members', { method: 'POST', tok, body: { email: 'two@example.test', role: 'manager', reason: REASON } })
  assert.equal(reAdd.status, 200)
  assert.equal((await reAdd.json()).role, 'manager')
  assert.equal(db.members.get('co-1|user-2').status, 'active')
  const already = await call(env, '/api/companies/co-1/members', { method: 'POST', tok, body: { email: 'two@example.test', role: 'admin', reason: REASON } })
  assert.equal(already.status, 400)
  const owner = await call(env, '/api/companies/co-1/members', { method: 'POST', tok, body: { email: 'admin@example.test', role: 'admin', reason: REASON } })
  assert.equal(owner.status, 400)
  const suspended = await call(env, '/api/companies/co-1/members', { method: 'POST', tok, body: { email: 'four@example.test', role: 'employee', reason: REASON } })
  assert.equal(suspended.status, 400)
  const missingUser = await call(env, '/api/companies/co-1/members', { method: 'POST', tok, body: { email: 'ghost@example.test', role: 'employee', reason: REASON } })
  assert.equal(missingUser.status, 404)
  const missingCompany = await call(env, '/api/companies/nope/members', { method: 'POST', tok, body: { email: 'two@example.test', role: 'employee', reason: REASON } })
  assert.equal(missingCompany.status, 404)
  const badRole = await call(env, '/api/companies/co-1/members', { method: 'POST', tok, body: { email: 'two@example.test', role: 'owner', reason: REASON } })
  assert.equal(badRole.status, 400)
  const noTok = await call(env, '/api/companies/co-1/members', { method: 'POST', body: { email: 'two@example.test', role: 'employee', reason: REASON } })
  assert.equal(noTok.status, 401)
  assert.equal(db.audits.filter((a) => a.action === 'member_added').length, 1)
})

test('method guards: PUT on the new user routes is 405', async () => {
  const { pub, tok } = await setup()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const res = await call(env, '/api/users', { method: 'PUT', tok, body: {} })
  assert.equal(res.status, 405)
  const res2 = await call(env, '/api/users/user-2/deactivate', { method: 'PUT', tok, body: {} })
  assert.equal(res2.status, 405)
})
