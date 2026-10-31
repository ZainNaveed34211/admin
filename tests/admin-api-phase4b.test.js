import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

function makeDb({ company = { id: 'co-1', owner_user_id: 'owner-1' }, members = null } = {}) {
  const rateCounts = new Map()
  const audits = []
  const rows = members || [
    { company_id: 'co-1', user_id: 'owner-1', role: 'owner', status: 'active', email: 'owner@example.test' },
    { company_id: 'co-1', user_id: 'user-2', role: 'manager', status: 'active', email: 'two@example.test' },
    { company_id: 'co-1', user_id: 'user-3', role: 'owner', status: 'active', email: 'three@example.test' },
  ]
  const bound = (sql, params) => ({
    sql,
    params,
    async first() {
      if (sql.includes('FROM sessions') && sql.includes('WHERE s.id')) {
        return { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
      }
      if (sql.includes('FROM admin_allowlist')) return { user_id: 'user-1' }
      if (sql.includes('SELECT count FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
      if (sql.includes('FROM companies WHERE id')) return params[0] === company.id ? company : null
      if (sql.includes('FROM company_members') && sql.includes("status = 'active'") && sql.includes('user_id = ?')) {
        return rows.find((m) => m.company_id === params[0] && m.user_id === params[1] && m.status === 'active') || null
      }
      if (sql.includes('COUNT(*)') && sql.includes("role = 'owner'")) {
        return { c: rows.filter((m) => m.company_id === params[0] && m.role === 'owner' && m.status === 'active').length }
      }
      return null
    },
    async all() {
      if (sql.includes('FROM company_members m LEFT JOIN')) {
        return { results: rows.map((m) => ({ user_id: m.user_id, role: m.role, status: m.status, department_id: null, joined_at: '2026-10-05T00:00:00.000Z', email: m.email })) }
      }
      return { results: [] }
    },
    async run() {
      if (sql.includes('INTO rate_limits')) {
        rateCounts.set(params[0], (rateCounts.get(params[0]) || 0) + 1)
      }
      return { meta: { changes: 1 } }
    },
  })
  return {
    audits,
    rows,
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
        if (st.sql.includes('UPDATE company_members SET role')) {
          const row = rows.find((m) => m.company_id === st.params[1] && m.user_id === st.params[2])
          if (row) row.role = st.params[0]
        }
        if (st.sql.includes("UPDATE company_members SET status = 'removed'")) {
          const row = rows.find((m) => m.company_id === st.params[0] && m.user_id === st.params[1])
          if (row) row.status = 'removed'
        }
        if (st.sql.includes('INTO admin_audit_log')) {
          audits.push({ admin_user_id: st.params[0], action: st.params[1], resource_type: st.params[2], resource_id: st.params[3], reason: st.params[4], success: st.params[5] })
        }
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

async function token(priv) {
  const nowSec = Math.floor(NOW / 1000)
  return signAssertionForTest(priv, { sub: 'user-1', sid: 'sess-1', aud: 'kluzar-admin-api', iat: nowSec, exp: nowSec + 300, jti: 'jti-1', mfa: true }, 'admin-assertion-v1')
}

function call(env, path, { origin = ADMIN_ORIGIN, tok = null, method = 'GET', body = null } = {}) {
  const headers = {}
  if (origin) headers.Origin = origin
  if (tok) headers.Authorization = `Bearer ${tok}`
  if (body !== null) headers['Content-Type'] = 'application/json'
  return worker.fetch(new Request(`https://admin-api.kluzar.com${path}`, { method, headers, body: body !== null ? JSON.stringify(body) : undefined }), env)
}

test('company detail returns company and members', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const res = await call(env, '/api/companies/co-1', { tok: await token(priv) })
  assert.equal(res.status, 200)
  const data = await res.json()
  assert.equal(data.company.id, 'co-1')
  assert.equal(data.members.length, 3)
})

test('role change and removal update members and audit', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const changed = await call(env, '/api/companies/co-1/members/user-2/role', { tok, method: 'POST', body: { role: 'admin', reason: 'Promoted to admin for team lead duties' } })
  assert.equal(changed.status, 200)
  const changedData = await changed.json()
  assert.equal(changedData.role, 'admin')
  assert.equal(changedData.previousRole, 'manager')
  const removed = await call(env, '/api/companies/co-1/members/user-2/remove', { tok, method: 'POST', body: { reason: 'Left the company, access revoked now' } })
  assert.equal(removed.status, 200)
  assert.equal((await removed.json()).status, 'removed')
  const again = await call(env, '/api/companies/co-1/members/user-2/remove', { tok, method: 'POST', body: { reason: 'Left the company, access revoked now' } })
  assert.equal(again.status, 404)
  assert.equal(db.audits.length, 2)
  assert.equal(db.audits[0].action, 'member_role_changed')
  assert.equal(db.audits[1].action, 'member_removed')
})

test('owner is protected and last owner-role member cannot be removed', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const ownerRole = await call(env, '/api/companies/co-1/members/owner-1/role', { tok, method: 'POST', body: { role: 'admin', reason: 'Trying to change the owner role here' } })
  assert.equal(ownerRole.status, 400)
  assert.equal((await ownerRole.json()).code, 'OWNER_PROTECTED')
  const ownerRemove = await call(env, '/api/companies/co-1/members/owner-1/remove', { tok, method: 'POST', body: { reason: 'Trying to remove the owner here ok' } })
  assert.equal(ownerRemove.status, 400)
  const soloDb = makeDb({ company: { id: 'co-2', owner_user_id: 'owner-9' }, members: [{ company_id: 'co-2', user_id: 'user-3', role: 'owner', status: 'active', email: 'three@example.test' }] })
  const envSolo = { DB: soloDb, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const lastOwner = await call(envSolo, '/api/companies/co-2/members/user-3/remove', { tok, method: 'POST', body: { reason: 'Trying to remove the last owner ok' } })
  assert.equal(lastOwner.status, 400)
  assert.equal((await lastOwner.json()).code, 'LAST_OWNER')
})

test('member changes reject bad input, missing company or member, and unauthenticated calls', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const badRole = await call(env, '/api/companies/co-1/members/user-2/role', { tok, method: 'POST', body: { role: 'super', reason: 'A long enough reason here' } })
  assert.equal(badRole.status, 400)
  const shortReason = await call(env, '/api/companies/co-1/members/user-2/remove', { tok, method: 'POST', body: { reason: 'short' } })
  assert.equal(shortReason.status, 400)
  const noCompany = await call(env, '/api/companies/co-404/members/user-2/remove', { tok, method: 'POST', body: { reason: 'A long enough reason here' } })
  assert.equal(noCompany.status, 404)
  const noMember = await call(env, '/api/companies/co-1/members/ghost/remove', { tok, method: 'POST', body: { reason: 'A long enough reason here' } })
  assert.equal(noMember.status, 404)
  const noAuth = await call(env, '/api/companies/co-1/members/user-2/remove', { method: 'POST', body: { reason: 'A long enough reason here' } })
  assert.equal(noAuth.status, 401)
  const wrongOrigin = await call(env, '/api/companies/co-1/members/user-2/remove', { tok, origin: 'https://evil.test', method: 'POST', body: { reason: 'A long enough reason here' } })
  assert.equal(wrongOrigin.status, 403)
})
