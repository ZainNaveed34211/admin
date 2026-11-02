import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import worker from '../worker/src/index.js'
import { signAssertionForTest } from '../worker/src/verify.js'

const ADMIN_ORIGIN = 'https://admin.kluzar.com'
const NOW = Date.now()
const REASON = 'Phase 2 test reason for this change'

function makeDb() {
  const rateCounts = new Map()
  const audits = []
  let usersInsert = null
  const sessionRow = { id: 'sess-1', user_id: 'user-1', expires_at: new Date(NOW + 3600 * 1000).toISOString(), scope: 'admin', user_status: 'active', user_email: 'admin@example.test' }
  return {
    audits,
    get usersInsert() { return usersInsert },
    prepare(sql) {
      const stmt = {
        bind(...params) {
          return {
            async first() {
              if (sql.includes('FROM sessions')) {
                if (params[0] !== sessionRow.id || params[1] !== sessionRow.user_id) return null
                return sessionRow
              }
              if (sql.includes('FROM admin_allowlist')) return { user_id: 'user-1' }
              if (sql.includes('FROM rate_limits')) return { count: rateCounts.get(params[0]) || 0 }
              return null
            },
            async run() {
              if (sql.includes('INTO rate_limits')) {
                rateCounts.set(params[0], (rateCounts.get(params[0]) || 0) + 1)
                return { meta: { changes: 1 } }
              }
              if (sql.includes('INSERT INTO users')) {
                usersInsert = params
                return { meta: { changes: 1 } }
              }
              if (sql.includes('INTO admin_audit_log')) {
                audits.push({ admin_user_id: params[0], action: params[1] })
                return { meta: { changes: 1 } }
              }
              return { meta: { changes: 0 } }
            },
          }
        },
      }
      return stmt
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

async function assertion(priv) {
  const nowSec = Math.floor(NOW / 1000)
  return signAssertionForTest(priv, { sub: 'user-1', sid: 'sess-1', aud: 'kluzar-admin-api', iat: nowSec, exp: nowSec + 300, jti: 'jti-1', mfa: true, step_up: true }, 'admin-assertion-v1')
}

test('user create sets must_change_password and a 48h temp password expiry', async () => {
  const { pub, priv } = await keypair()
  const db = makeDb()
  const env = { DB: db, ADMIN_ASSERTION_PUBLIC_KEY: JSON.stringify(pub), IP_HASH_SECRET: 'test-ip-hash-secret' }
  const token = await assertion(priv)
  const res = await worker.fetch(new Request('https://admin-api.kluzar.com/api/users', {
    method: 'POST',
    headers: { Origin: ADMIN_ORIGIN, Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: 'newuser@example.test', firstName: 'New', lastName: 'User', phone: '', plan: 'free', reason: REASON }),
  }), env)
  assert.equal(res.status, 200, JSON.stringify(await res.clone().json().catch(() => ({}))))
  const body = await res.json()
  assert.equal(body.ok, true)
  assert.equal(body.tempPassword.length, 20)
  assert.ok(db.usersInsert, 'users INSERT must have run')
  assert.equal(db.usersInsert[12], 1, 'must_change_password must be 1')
  const expiryMs = Date.parse(db.usersInsert[13]) - Date.now()
  assert.ok(expiryMs > 47 * 60 * 60 * 1000 && expiryMs < 49 * 60 * 60 * 1000, `expiry must be ~48h, got ${expiryMs}ms`)
})

test('wrangler disables workers.dev and preview URLs', async () => {
  const toml = readFileSync(new URL('../wrangler.toml', import.meta.url), 'utf8')
  assert.ok(toml.includes('workers_dev = false'))
  assert.ok(toml.includes('preview_urls = false'))
})
