import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()
const REASON = 'Phase 3 test reason for this change'

function makeDb(options = {}) {
  const rateCounts = new Map()
  const audits = []
  const sessionRow = options.session !== undefined ? options.session : { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
  const allowlisted = options.allowlisted !== false
  const exportRows = options.exportRows || []
  return {
    audits,
    prepare(sql) {
      const bound = (params) => {
        return {
          async first() {
            if (sql.includes('FROM sessions')) {
              if (!sessionRow) return null
              if (params[0] !== sessionRow.id || params[1] !== sessionRow.user_id) return null
              return sessionRow
            }
            if (sql.includes('FROM admin_allowlist')) return allowlisted ? { user_id: 'user-1' } : null
            if (sql.includes('FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
            if (sql.includes('COUNT(*) AS c FROM admin_audit_log')) return { c: exportRows.length }
            return null
          },
          async all() {
            if (sql.includes('FROM admin_audit_log')) return { results: exportRows }
            return { results: [] }
          },
          async run() {
            if (sql.includes('INTO rate_limits')) {
              rateCounts.set(params[0], (rateCounts.get(params[0]) || 0) + 1)
              return { meta: { changes: 1 } }
            }
            if (sql.includes('INTO admin_audit_log')) {
              audits.push({ params: [...params] })
              return { meta: { changes: 1 } }
            }
            return { meta: { changes: 0 } }
          },
        }
      }
      return {
        bind: (...params) => bound(params),
        first: () => bound([]).first(),
        all: () => bound([]).all(),
        run: () => bound([]).run(),
      }
    },
    async batch(statements) {
      for (const st of statements) await st.run()
      return []
    },
  }
}

async function keypair() {
  const pair = await crypto.subtle.generateKey({ name: 'Ed25519' }, true, ['sign', 'verify'])
  const pub = await crypto.subtle.exportKey('jwk', pair.publicKey)
  const priv = await crypto.subtle.exportKey('jwk', pair.privateKey)
  return { pub, priv }
}

async function assertion(priv, overrides = {}) {
  const nowSec = Math.floor(NOW / 1000)
  return signAssertionForTest(priv, { sub: 'user-1', sid: 'sess-1', aud: 'kluzar-admin-api', iat: nowSec, exp: nowSec + 300, jti: 'jti-1', mfa: true, ...overrides }, 'admin-assertion-v1')
}

function call(env, path, { method = 'GET', origin = ADMIN_ORIGIN, token = null, body = undefined } = {}) {
  const headers = {}
  if (origin) headers.Origin = origin
  if (token) headers.Authorization = `Bearer ${token}`
  if (body !== undefined) headers['Content-Type'] = 'application/json'
  return worker.fetch(new Request(`https://admin-api.kluzar.com${path}`, { method, headers, body }), env)
}

test('sensitive routes require a fresh step-up assertion; reads do not', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const plain = await assertion(priv)
  const denied = await call(env, '/api/users', { method: 'POST', token: plain, body: JSON.stringify({ email: 'x@example.test', plan: 'free', reason: REASON }) })
  assert.equal(denied.status, 403)
  assert.equal((await denied.json()).code, 'STEP_UP_REQUIRED')
  const fresh = await assertion(priv, { step_up: true })
  const ok = await call(env, '/api/users', { method: 'POST', token: fresh, body: JSON.stringify({ email: 'x@example.test', plan: 'free', reason: REASON }) })
  assert.equal(ok.status, 200)
  const stale = await assertion(priv, { step_up: true, iat: Math.floor(NOW / 1000) - 100, exp: Math.floor(NOW / 1000) + 500 })
  const staleRes = await call(env, '/api/users', { method: 'POST', token: stale, body: JSON.stringify({ email: 'y@example.test', plan: 'free', reason: REASON }) })
  assert.equal(staleRes.status, 403)
  assert.equal((await staleRes.json()).code, 'STEP_UP_REQUIRED')
  const read = await call(env, '/api/overview', { token: plain })
  assert.equal(read.status, 200)
})

test('denial audits are throttled to 10 per minute per ip', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const good = await assertion(priv)
  const parts = good.split('.')
  const bad = `${parts[0]}.${parts[1]}.${'A'.repeat(parts[2].length)}`
  for (let i = 0; i < 12; i++) {
    const res = await call(env, '/api/auth/verify', { method: 'POST', token: bad })
    assert.equal(res.status, 401)
  }
  const denied = db.audits.filter((a) => a.params[1] === 'admin_verify_denied')
  assert.equal(denied.length, 10)
})

test('csv export prefixes formula-like values', async () => {
  const { pub, priv } = await keypair()
  const rows = [
    { id: 1, admin_user_id: 'user-1', action: 'audit_exported', resource_type: 'audit_log', resource_id: '', reason: '=2+5', success: 1, correlation_id: 'c1', created_at: '2026-11-02T00:00:00.000Z' },
    { id: 2, admin_user_id: 'user-1', action: 'audit_exported', resource_type: 'audit_log', resource_id: '', reason: '+cmd', success: 1, correlation_id: 'c2', created_at: '2026-11-02T00:00:00.000Z' },
    { id: 3, admin_user_id: 'user-1', action: 'audit_exported', resource_type: 'audit_log', resource_id: '', reason: '-rm', success: 1, correlation_id: 'c3', created_at: '2026-11-02T00:00:00.000Z' },
    { id: 4, admin_user_id: 'user-1', action: 'audit_exported', resource_type: 'audit_log', resource_id: '', reason: '@user', success: 1, correlation_id: 'c4', created_at: '2026-11-02T00:00:00.000Z' },
    { id: 5, admin_user_id: 'user-1', action: 'audit_exported', resource_type: 'audit_log', resource_id: '', reason: '\tfoo', success: 1, correlation_id: 'c5', created_at: '2026-11-02T00:00:00.000Z' },
    { id: 6, admin_user_id: 'user-1', action: 'audit_exported', resource_type: 'audit_log', resource_id: '', reason: '\rbar', success: 1, correlation_id: 'c6', created_at: '2026-11-02T00:00:00.000Z' },
    { id: 7, admin_user_id: 'user-1', action: 'audit_exported', resource_type: 'audit_log', resource_id: '', reason: 'plain', success: 1, correlation_id: 'c7', created_at: '2026-11-02T00:00:00.000Z' },
  ]
  const db = makeDb({ exportRows: rows })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const token = await assertion(priv, { step_up: true })
  const res = await call(env, '/api/audit-log/export', { token })
  assert.equal(res.status, 200)
  const csv = await res.text()
  assert.ok(csv.includes("'=2+5"), csv)
  assert.ok(csv.includes("'+cmd"), csv)
  assert.ok(csv.includes("'-rm"), csv)
  assert.ok(csv.includes("'@user"), csv)
  assert.ok(csv.includes("'\tfoo"), csv)
  assert.ok(csv.includes(`"'\rbar"`), csv)
  assert.ok(csv.includes(',plain,'), csv)
})

test('mutation bodies over 16KB are rejected; bad JSON is rejected', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const token = await assertion(priv, { step_up: true })
  const big = await call(env, '/api/users', { method: 'POST', token, body: JSON.stringify({ email: 'big@example.test', plan: 'free', reason: 'x'.repeat(17000) }) })
  assert.equal(big.status, 413)
  assert.equal((await big.json()).code, 'BODY_TOO_LARGE')
  const bad = await call(env, '/api/users', { method: 'POST', token, body: '{not json' })
  assert.equal(bad.status, 400)
  assert.equal((await bad.json()).code, 'INVALID_BODY')
})

test('malformed percent-encoding in ids returns 400 INVALID_ID', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const res = await call(env, '/api/users/%E0%A4%A')
  assert.equal(res.status, 400)
  assert.equal((await res.json()).code, 'INVALID_ID')
})

test('internal failures return a generic 500 with CORS and security headers', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const token = await assertion(priv)
  const res = await call(env, '/api/overview', { token })
  assert.equal(res.status, 500)
  assert.equal((await res.json()).code, 'UNAVAILABLE')
  assert.equal(res.headers.get('Access-Control-Allow-Origin'), ADMIN_ORIGIN)
  assert.equal(res.headers.get('X-Content-Type-Options'), 'nosniff')
})

test('assertion failures return a generic Unauthorized body, never the internal reason', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const good = await assertion(priv)
  const tparts = good.split('.')
  const tampered = `${tparts[0]}.${tparts[1]}.${'A'.repeat(tparts[2].length)}`
  const res = await call(env, '/api/auth/verify', { method: 'POST', token: tampered })
  assert.equal(res.status, 401)
  const body = await res.json()
  assert.equal(body.error, 'Unauthorized')
  assert.equal(body.code, 'UNAUTHORIZED')
})

test('audit rows record the HMAC ip hash', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const token = await assertion(priv)
  const res = await call(env, '/api/auth/verify', { method: 'POST', token })
  assert.equal(res.status, 200)
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('test-ip-hash-secret'), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign'])
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(''))
  const expected = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, '0')).join('').slice(0, 32)
  const row = db.audits.find((a) => a.params[1] === 'admin_session_verified')
  assert.ok(row, 'admin_session_verified audit must exist')
  assert.equal(row.params[8], expected)
})

test('audit ip_hash migration adds the column', async () => {
  const sql = readFileSync(new URL('../migrations/0002_admin_audit_ip_hash.sql', import.meta.url), 'utf8')
  assert.ok(sql.includes('ALTER TABLE admin_audit_log ADD COLUMN ip_hash TEXT'))
})
