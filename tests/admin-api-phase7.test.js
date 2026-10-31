import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

const ROWS = [
  { id: 1, admin_user_id: 'user-1', action: 'admin_login', resource_type: 'api', resource_id: '', reason: '', success: 1, correlation_id: 'c1', created_at: '2026-10-31T10:00:00.000Z' },
  { id: 2, admin_user_id: 'user-1', action: 'entitlement_corrected', resource_type: 'entitlement', resource_id: 'user-9', reason: 'Paid, "manual" invoice, grant Growth', success: 1, correlation_id: 'c2', created_at: '2026-10-31T11:00:00.000Z' },
  { id: 3, admin_user_id: 'user-2', action: 'admin_login', resource_type: 'api', resource_id: '', reason: '', success: 0, correlation_id: 'c3', created_at: '2026-10-31T12:00:00.000Z' },
]

function makeDb() {
  const rateCounts = new Map()
  const audits = []
  const bound = (sql, params) => ({
    sql,
    params,
    async first() {
      if (sql.includes('FROM sessions') && sql.includes('WHERE s.id')) {
        return { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
      }
      if (sql.includes('FROM admin_allowlist')) return { user_id: 'user-1' }
      if (sql.includes('SELECT count FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
      if (sql.includes('COUNT(*) AS c')) {
        let filtered = ROWS
        if (sql.includes('action = ?')) filtered = filtered.filter((r) => r.action === params[0])
        return { c: filtered.length }
      }
      return null
    },
    async all() {
      if (sql.includes('FROM admin_audit_log')) {
        let filtered = ROWS
        if (sql.includes('action = ?')) filtered = filtered.filter((r) => r.action === params[0])
        const limit = params[params.length - 1]
        return { results: filtered.slice(0, limit) }
      }
      return { results: [] }
    },
    async run() {
      if (sql.includes('INTO rate_limits')) {
        rateCounts.set(params[0], (rateCounts.get(params[0]) || 0) + 1)
      }
      if (sql.includes('INTO admin_audit_log')) {
        audits.push({ action: params[1], resource_type: params[2], reason: params[4] })
      }
      return { meta: { changes: 1 } }
    },
  })
  return {
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

test('audit export returns escaped CSV, applies filters, and audits itself', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const res = await call(env, '/api/audit-log/export', { tok })
  assert.equal(res.status, 200)
  assert.equal(res.headers.get('Content-Type'), 'text/csv; charset=utf-8')
  assert.equal(res.headers.get('X-Total-Count'), '3')
  assert.equal(res.headers.get('X-Export-Truncated'), 'false')
  const csv = await res.text()
  const lines = csv.trim().split('\n')
  assert.equal(lines[0], 'id,admin_user_id,action,resource_type,resource_id,reason,success,correlation_id,created_at')
  assert.equal(lines.length, 4)
  assert.ok(lines[2].includes('"Paid, ""manual"" invoice, grant Growth"'))
  assert.equal(db.audits.length, 1)
  assert.equal(db.audits[0].action, 'audit_exported')
  const filtered = await call(env, '/api/audit-log/export?action=admin_login', { tok })
  const filteredCsv = await filtered.text()
  assert.equal(filteredCsv.trim().split('\n').length, 3)
})

test('audit export rejects unauthenticated, wrong origin, and wrong method', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const noAuth = await call(env, '/api/audit-log/export')
  assert.equal(noAuth.status, 401)
  const wrongOrigin = await call(env, '/api/audit-log/export', { tok, origin: 'https://evil.test' })
  assert.equal(wrongOrigin.status, 403)
  const wrongMethod = await call(env, '/api/audit-log/export', { tok, method: 'DELETE' })
  assert.equal(wrongMethod.status, 405)
})
