import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

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

test('services reports live health, failures, and unknown account-api', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (url) => {
    if (String(url).includes('seo-api')) return new Response(JSON.stringify({ ok: true }), { status: 200 })
    if (String(url).includes('manage-api')) throw new Error('network down')
    if (String(url).includes('business-api')) return new Response('error', { status: 500 })
    if (String(url).includes('dashboard-api')) return new Response(JSON.stringify({ ok: true }), { status: 200 })
    throw new Error('unexpected url')
  }
  try {
    const { pub, priv } = await keypair()
    const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
    const res = await call(env, '/api/services', { tok: await token(priv) })
    assert.equal(res.status, 200)
    const data = await res.json()
    assert.equal(data.services.length, 6)
    const byName = Object.fromEntries(data.services.map((s) => [s.service, s]))
    assert.equal(byName['seo-api'].ok, true)
    assert.equal(byName['seo-api'].status, 200)
    assert.equal(byName['manage-api'].ok, false)
    assert.equal(byName['manage-api'].status, null)
    assert.equal(byName['business-api'].ok, false)
    assert.equal(byName['business-api'].status, 500)
    assert.equal(byName['dashboard-api'].ok, true)
    assert.equal(byName['admin-api'].ok, true)
    assert.equal(byName['account-api'].ok, null)
    assert.equal(typeof byName['seo-api'].ms, 'number')
    assert.equal(typeof data.checkedAt, 'string')
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('services rejects unauthenticated, wrong origin, and wrong method', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const noAuth = await call(env, '/api/services')
  assert.equal(noAuth.status, 401)
  const wrongOrigin = await call(env, '/api/services', { tok, origin: 'https://evil.test' })
  assert.equal(wrongOrigin.status, 403)
  const wrongMethod = await call(env, '/api/services', { tok, method: 'DELETE' })
  assert.equal(wrongMethod.status, 405)
})
