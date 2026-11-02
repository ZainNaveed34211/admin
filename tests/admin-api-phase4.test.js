import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

function makeDb({ entitlement = { plan: 'free', status: 'active', provider: 'manual', provider_subscription_id: 'sub-1' } } = {}) {
  const rateCounts = new Map()
  const audits = []
  let current = entitlement ? { ...entitlement } : null
  const bound = (sql, params) => ({
    sql,
    params,
    async first() {
      if (sql.includes('FROM sessions') && sql.includes('WHERE s.id')) {
        return { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
      }
      if (sql.includes('FROM admin_allowlist')) return { user_id: 'user-1' }
      if (sql.includes('SELECT count FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
      if (sql.includes('FROM entitlements')) return current
      return null
    },
    async all() {
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
    get entitlement() {
      return current
    },
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
        if (st.sql.includes('UPDATE entitlements')) {
          if (current) {
            current.plan = st.params[0]
            current.status = st.params[1]
          }
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
  return signAssertionForTest(priv, { sub: 'user-1', sid: 'sess-1', aud: 'kluzar-admin-api', iat: nowSec, exp: nowSec + 300, jti: 'jti-1', mfa: true, step_up: true }, 'admin-assertion-v1')
}

function call(env, path, { origin = ADMIN_ORIGIN, tok = null, method = 'POST', body = null } = {}) {
  const headers = {}
  if (origin) headers.Origin = origin
  if (tok) headers.Authorization = `Bearer ${tok}`
  if (body !== null) headers['Content-Type'] = 'application/json'
  return worker.fetch(new Request(`https://admin-api.kluzar.com${path}`, { method, headers, body: body !== null ? JSON.stringify(body) : undefined }), env)
}

test('entitlement correction updates plan and audits it, payment fields untouched', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const res = await call(env, '/api/users/user-9/entitlement', { tok: await token(priv), body: { plan: 'growth', status: 'active', reason: 'Customer paid via manual invoice, grant Growth' } })
  assert.equal(res.status, 200)
  const data = await res.json()
  assert.equal(data.plan, 'growth')
  assert.equal(data.previousPlan, 'free')
  assert.equal(db.entitlement.plan, 'growth')
  assert.equal(db.entitlement.provider, 'manual')
  assert.equal(db.entitlement.provider_subscription_id, 'sub-1')
  assert.equal(db.audits.length, 1)
  assert.equal(db.audits[0].action, 'entitlement_corrected')
  assert.equal(db.audits[0].resource_id, 'user-9')
  assert.equal(db.audits[0].reason, 'Customer paid via manual invoice, grant Growth')
})

test('correction rejects short reason, invalid plan, and no-change', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const tok = await token(priv)
  const short = await call(env, '/api/users/user-9/entitlement', { tok, body: { plan: 'growth', reason: 'too short' } })
  assert.equal(short.status, 400)
  assert.equal((await short.json()).code, 'INVALID_REASON')
  const badPlan = await call(env, '/api/users/user-9/entitlement', { tok, body: { plan: 'ultra', reason: 'A long enough reason here' } })
  assert.equal(badPlan.status, 400)
  assert.equal((await badPlan.json()).code, 'INVALID_PLAN')
  const noChange = await call(env, '/api/users/user-9/entitlement', { tok, body: { plan: 'free', status: 'active', reason: 'A long enough reason here' } })
  assert.equal(noChange.status, 400)
  assert.equal((await noChange.json()).code, 'NO_CHANGE')
  assert.equal(db.audits.length, 0)
})

test('correction rejects unauthenticated, wrong origin, and missing entitlement', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const tok = await token(priv)
  const noAuth = await call(env, '/api/users/user-9/entitlement', { body: { plan: 'growth', reason: 'A long enough reason here' } })
  assert.equal(noAuth.status, 401)
  const wrongOrigin = await call(env, '/api/users/user-9/entitlement', { tok, origin: 'https://evil.test', body: { plan: 'growth', reason: 'A long enough reason here' } })
  assert.equal(wrongOrigin.status, 403)
  const envNoEnt = { DB: makeDb({ entitlement: null }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const missing = await call(envNoEnt, '/api/users/user-9/entitlement', { tok, body: { plan: 'growth', reason: 'A long enough reason here' } })
  assert.equal(missing.status, 404)
})

test('correction rate limit trips after 20 attempts', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const tok = await token(priv)
  let last = null
  for (let i = 0; i < 21; i++) {
    last = await call(env, '/api/users/user-9/entitlement', { tok, body: { plan: 'growth', reason: 'x' } })
  }
  assert.equal(last.status, 429)
})
