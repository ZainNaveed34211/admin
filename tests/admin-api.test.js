import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

function makeDb({ session = null, allowlisted = true } = {}) {
  const rateCounts = new Map()
  const auditRows = []
  return {
    auditRows,
    prepare(sql) {
      const stmt = {
        bind(...params) {
          return {
            async first() {
              if (sql.includes('FROM sessions')) {
                if (!session) return null
                if (params[0] !== session.id || params[1] !== session.user_id) return null
                return session
              }
              if (sql.includes('FROM admin_allowlist')) {
                return allowlisted && params[0] === session?.user_id ? { user_id: params[0] } : null
              }
              if (sql.includes('FROM rate_limits')) {
                const count = rateCounts.get(params[0]) || 0
                return { count }
              }
              return null
            },
            async run() {
              if (sql.includes('INTO rate_limits')) {
                const key = params[0]
                rateCounts.set(key, (rateCounts.get(key) || 0) + 1)
                return {}
              }
              if (sql.includes('INTO admin_audit_log')) {
                auditRows.push({ admin_user_id: params[0], action: params[1], success: params[5] })
                return {}
              }
              return {}
            },
          }
        },
      }
      return stmt
    },
  }
}

function sessionRow(overrides = {}) {
  return {
    id: 'sess-1',
    user_id: 'user-1',
    expires_at: new Date(NOW + 3600 * 1000).toISOString(),
    user_status: 'active',
    user_email: 'admin@example.test',
    ...overrides,
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
  const claims = {
    sub: 'user-1',
    sid: 'sess-1',
    aud: 'kluzar-admin-api',
    iat: nowSec,
    exp: nowSec + 300,
    jti: 'jti-1',
    mfa: true,
    ...overrides,
  }
  return signAssertionForTest(priv, claims, overrides.kid || 'admin-assertion-v1')
}

function call(env, path, { method = 'GET', origin = ADMIN_ORIGIN, token = null } = {}) {
  const headers = {}
  if (origin) headers.Origin = origin
  if (token) headers.Authorization = `Bearer ${token}`
  return worker.fetch(new Request(`https://admin-api.kluzar.com${path}`, { method, headers }), env)
}

test('health allows the admin origin and rejects others', async () => {
  const env = { DB: makeDb(), ADMIN_ASSERTION_PUBLIC_KEY: '{}' }
  const ok = await call(env, '/api/health')
  assert.equal(ok.status, 200)
  assert.equal((await ok.json()).ok, true)
  const bad = await call(env, '/api/health', { origin: 'https://evil.test' })
  assert.equal(bad.status, 403)
})

test('verify accepts a valid admin assertion and audits the login', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb({ session: sessionRow() })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const token = await assertion(priv)
  const res = await call(env, '/api/auth/verify', { method: 'POST', token })
  assert.equal(res.status, 200)
  const body = await res.json()
  assert.equal(body.admin, true)
  assert.equal(body.userId, 'user-1')
  assert.equal(db.auditRows.length, 1)
  assert.equal(db.auditRows[0].action, 'admin_login')
})

test('verify rejects wrong kid, wrong audience, expiry, and tampering', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb({ session: sessionRow() })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const cases = [
    await assertion(priv, { kid: 'other-v1' }),
    await assertion(priv, { aud: 'kluzar-manage-api' }),
    await assertion(priv, { exp: Math.floor(NOW / 1000) - 10 }),
  ]
  for (const token of cases) {
    const res = await call(env, '/api/auth/verify', { method: 'POST', token })
    assert.equal(res.status, 401)
  }
  const good = await assertion(priv)
  const parts = good.split('.')
  const tampered = `${parts[0]}.${parts[1]}.${'A'.repeat(parts[2].length)}`
  const res = await call(env, '/api/auth/verify', { method: 'POST', token: tampered })
  assert.equal(res.status, 401)
})

test('verify rejects non-allowlisted users, missing MFA, dead sessions, inactive accounts', async () => {
  const { pub, priv } = await keypair()
  const token = await assertion(priv)
  const envNoAllow = { DB: makeDb({ session: sessionRow(), allowlisted: false }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  assert.equal((await call(envNoAllow, '/api/auth/verify', { method: 'POST', token })).status, 403)
  const noMfa = await assertion(priv, { mfa: false })
  const envOk = { DB: makeDb({ session: sessionRow() }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  assert.equal((await call(envOk, '/api/auth/verify', { method: 'POST', token: noMfa })).status, 403)
  const envDead = { DB: makeDb({ session: sessionRow({ expires_at: new Date(NOW - 1000).toISOString() }) }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  assert.equal((await call(envDead, '/api/auth/verify', { method: 'POST', token })).status, 401)
  const envInactive = { DB: makeDb({ session: sessionRow({ user_status: 'suspended' }) }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  assert.equal((await call(envInactive, '/api/auth/verify', { method: 'POST', token })).status, 401)
  const envNoSession = { DB: makeDb({ session: null }), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  assert.equal((await call(envNoSession, '/api/auth/verify', { method: 'POST', token })).status, 401)
})

test('verify rejects wrong origin, missing bearer, and unknown paths', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb({ session: sessionRow() })
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const token = await assertion(priv)
  assert.equal((await call(env, '/api/auth/verify', { method: 'POST', token, origin: 'https://evil.test' })).status, 403)
  assert.equal((await call(env, '/api/auth/verify', { method: 'POST' })).status, 401)
  assert.equal((await call(env, '/api/nope')).status, 404)
  const opt = await call(env, '/api/auth/verify', { method: 'OPTIONS' })
  assert.equal(opt.status, 204)
  assert.equal(opt.headers.get('Access-Control-Allow-Origin'), ADMIN_ORIGIN)
})
