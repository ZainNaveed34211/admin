import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

const ROWS = [
  { user_id: 'user-1', email: 'one@example.test', plan: 'free', status: 'active', provider: null, provider_subscription_id: null, current_period_end: null, updated_at: '2026-10-30T00:00:00.000Z' },
  { user_id: 'user-2', email: 'two@example.test', plan: 'growth', status: 'active', provider: 'manual', provider_subscription_id: 'sub-2', current_period_end: '2026-11-30T00:00:00.000Z', updated_at: '2026-10-31T00:00:00.000Z' },
  { user_id: 'user-3', email: 'three@example.test', plan: 'max', status: 'cancelled', provider: 'manual', provider_subscription_id: 'sub-3', current_period_end: '2026-11-15T00:00:00.000Z', updated_at: '2026-10-29T00:00:00.000Z' },
]

function filterRows(sql, params) {
  let idx = 0
  let plan = null
  let status = null
  if (sql.includes('e.plan = ?')) plan = params[idx++]
  if (sql.includes('e.status = ?')) status = params[idx++]
  return ROWS.filter((r) => (!plan || r.plan === plan) && (!status || r.status === status))
}

function makeDb() {
  const rateCounts = new Map()
  const bound = (sql, params) => ({
    sql,
    params,
    async first() {
      if (sql.includes('FROM sessions') && sql.includes('WHERE s.id')) {
        return { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
      }
      if (sql.includes('FROM admin_allowlist')) return { user_id: 'user-1' }
      if (sql.includes('SELECT count FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
      if (sql.includes('COUNT(*) AS total')) return { total: filterRows(sql, params).length }
      return null
    },
    async all() {
      if (sql.includes('FROM entitlements e')) {
        const filtered = filterRows(sql, params)
        const limit = params[params.length - 2]
        const offset = params[params.length - 1]
        return { results: filtered.slice(offset, offset + limit) }
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
    prepare(sql) {
      return {
        bind: (...params) => bound(sql, params),
        first: () => bound(sql, []).first(),
        all: () => bound(sql, []).all(),
        run: () => bound(sql, []).run(),
      }
    },
    async batch(statements) {
      return statements.map(() => ({ meta: { changes: 1 } }))
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

function call(env, path, { origin = ADMIN_ORIGIN, tok = null, method = 'GET' } = {}) {
  const headers = {}
  if (origin) headers.Origin = origin
  if (tok) headers.Authorization = `Bearer ${tok}`
  return worker.fetch(new Request(`https://admin-api.kluzar.com${path}`, { method, headers }), env)
}

test('payments list returns records with emails and supports filters', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const all = await call(env, '/api/payments', { tok })
  assert.equal(all.status, 200)
  const allData = await all.json()
  assert.equal(allData.total, 3)
  assert.equal(allData.payments.length, 3)
  assert.equal(allData.payments[0].email, 'one@example.test')
  const growth = await call(env, '/api/payments?plan=growth', { tok })
  const growthData = await growth.json()
  assert.equal(growthData.total, 1)
  assert.equal(growthData.payments[0].plan, 'growth')
  assert.equal(growthData.payments[0].provider_subscription_id, 'sub-2')
  const cancelled = await call(env, '/api/payments?status=cancelled', { tok })
  const cancelledData = await cancelled.json()
  assert.equal(cancelledData.total, 1)
  assert.equal(cancelledData.payments[0].status, 'cancelled')
})

test('payments rejects unauthenticated, wrong origin, and wrong method', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const noAuth = await call(env, '/api/payments')
  assert.equal(noAuth.status, 401)
  const wrongOrigin = await call(env, '/api/payments', { tok, origin: 'https://evil.test' })
  assert.equal(wrongOrigin.status, 403)
  const wrongMethod = await call(env, '/api/payments', { tok, method: 'DELETE' })
  assert.equal(wrongMethod.status, 405)
})
