import test from 'node:test'
import assert from 'node:assert/strict'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()

function makeReadDb() {
  const rateCounts = new Map()
  const users = [
    { id: 'user-1', email: 'one@example.test', first_name: 'One', last_name: 'User', phone: '', status: 'active', email_verified: 1, mfa_enabled: 1, created_at: '2026-10-01T00:00:00.000Z', plan: 'growth', plan_status: 'active', current_period_end: '2026-11-01' },
    { id: 'user-2', email: 'two@example.test', first_name: 'Two', last_name: 'User', phone: '', status: 'pending_mfa', email_verified: 0, mfa_enabled: 0, created_at: '2026-10-20T00:00:00.000Z', plan: 'free', plan_status: 'active', current_period_end: '' },
  ]
  return {
    prepare(sql) {
      const bound = (params) => {
        return {
          async first() {
              if (sql.includes('FROM sessions') && sql.includes('WHERE s.id')) {
                return { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
              }
              if (sql.includes('FROM admin_allowlist')) return { user_id: 'user-1' }
              if (sql.includes('FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
              if (sql.includes('SELECT COUNT(*) AS c FROM users') && !sql.includes('LEFT JOIN')) return { c: 2 }
              if (sql.includes('SELECT COUNT(*) AS c FROM users') && sql.includes('LEFT JOIN')) return { c: 2 }
              if (sql.includes('FROM companies') && sql.includes('COUNT(*)')) return { c: 3 }
              if (sql.includes('FROM company_members') && sql.includes('COUNT(*)')) return { c: 5 }
              if (sql.includes('FROM sessions') && sql.includes('COUNT(*)')) return { c: 1 }
              if (sql.includes('MAX(created_at)')) return { last_login: '2026-10-30T10:00:00.000Z' }
              if (sql.includes('FROM users u LEFT JOIN entitlements') && sql.includes('WHERE u.id')) return users[0]
              return null
            },
            async all() {
              if (sql.includes('GROUP BY status') && sql.includes('FROM users')) return { results: [{ status: 'active', c: 1 }, { status: 'pending_mfa', c: 1 }] }
              if (sql.includes('GROUP BY plan')) return { results: [{ plan: 'growth', c: 1 }, { plan: 'free', c: 1 }] }
              if (sql.includes('GROUP BY status') && sql.includes('FROM entitlements')) return { results: [{ status: 'active', c: 2 }] }
              if (sql.includes('FROM users u LEFT JOIN entitlements')) return { results: users }
              if (sql.includes('FROM companies WHERE owner_user_id')) return { results: [{ id: 'co-1', name: 'Acme', created_at: '2026-10-05T00:00:00.000Z', updated_at: '2026-10-05T00:00:00.000Z' }] }
              if (sql.includes('FROM company_members m JOIN companies')) return { results: [{ company_id: 'co-1', role: 'owner', status: 'active', joined_at: '2026-10-05T00:00:00.000Z', company_name: 'Acme' }] }
              if (sql.includes('FROM audit_events')) return { results: [{ event_type: 'login', ok: 1, detail: '', created_at: '2026-10-30T10:00:00.000Z' }] }
              if (sql.includes('FROM companies c LEFT JOIN users')) return { results: [{ id: 'co-1', name: 'Acme', owner_user_id: 'user-1', owner_email: 'one@example.test', created_at: '2026-10-05T00:00:00.000Z', updated_at: '2026-10-05T00:00:00.000Z', member_count: 2 }] }
              if (sql.includes('FROM admin_audit_log')) return { results: [{ id: 1, admin_user_id: 'user-1', action: 'admin_login', resource_type: 'session', resource_id: '', reason: '', success: 1, correlation_id: 'c-1', created_at: '2026-10-30T10:00:00.000Z' }] }
              return { results: [] }
            },
            async run() {
              if (sql.includes('INTO rate_limits')) {
                rateCounts.set(params[0], (rateCounts.get(params[0]) || 0) + 1)
              }
              return {}
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

function call(env, path, { origin = ADMIN_ORIGIN, token: tok = null } = {}) {
  const headers = {}
  if (origin) headers.Origin = origin
  if (tok) headers.Authorization = `Bearer ${tok}`
  return worker.fetch(new Request(`https://admin-api.kluzar.com${path}`, { headers }), env)
}

test('overview returns real counts and payments unavailable', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeReadDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const res = await call(env, '/api/overview?from=2026-10-01&to=2026-10-31', { token: await token(priv) })
  assert.equal(res.status, 200)
  const body = await res.json()
  assert.equal(body.users.total, 2)
  assert.equal(body.users.byStatus.length, 2)
  assert.equal(body.companies.total, 3)
  assert.equal(body.companies.memberships, 5)
  assert.equal(body.sessionsActive, 1)
  assert.equal(body.payments, null)
})

test('overview rejects an inverted or oversized date range', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeReadDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  assert.equal((await call(env, '/api/overview?from=2026-10-31&to=2026-10-01', { token: tok })).status, 400)
  assert.equal((await call(env, '/api/overview?from=2020-01-01&to=2026-10-31', { token: tok })).status, 400)
})

test('users list never exposes secrets and detail joins companies', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeReadDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const list = await call(env, '/api/users', { token: tok })
  assert.equal(list.status, 200)
  const listBody = await list.json()
  assert.equal(listBody.total, 2)
  assert.equal(listBody.users.length, 2)
  for (const u of listBody.users) {
    assert.equal('password_hash' in u, false)
    assert.equal('token_hash' in u, false)
    assert.equal('csrf_token' in u, false)
  }
  const detail = await call(env, '/api/users/user-1', { token: tok })
  assert.equal(detail.status, 200)
  const detailBody = await detail.json()
  assert.equal(detailBody.user.id, 'user-1')
  assert.equal(detailBody.ownedCompanies.length, 1)
  assert.equal(detailBody.memberships.length, 1)
  assert.equal(detailBody.lastLogin, '2026-10-30T10:00:00.000Z')
  assert.equal('ip_hash' in detailBody.user, false)
  for (const e of detailBody.recentAudit) assert.equal('ip_hash' in e, false)
})

test('companies and audit log lists return rows', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeReadDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  const companies = await call(env, '/api/companies', { token: tok })
  assert.equal(companies.status, 200)
  const companiesBody = await companies.json()
  assert.equal(companiesBody.total, 3)
  assert.equal(companiesBody.companies[0].member_count, 2)
  const audit = await call(env, '/api/audit-log', { token: tok })
  assert.equal(audit.status, 200)
  const auditBody = await audit.json()
  assert.equal(auditBody.entries.length, 1)
  assert.equal(auditBody.entries[0].action, 'admin_login')
})

test('reads reject unauthenticated, wrong origin, and over-limit callers', async () => {
  const { pub, priv } = await keypair()
  const env = { DB: makeReadDb(), ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub) }
  const tok = await token(priv)
  assert.equal((await call(env, '/api/overview')).status, 401)
  assert.equal((await call(env, '/api/overview', { token: tok, origin: 'https://evil.test' })).status, 403)
  let last = 200
  for (let i = 0; i < 61; i++) {
    last = (await call(env, '/api/overview', { token: tok })).status
  }
  assert.equal(last, 429)
})
