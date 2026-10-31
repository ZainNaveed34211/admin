CREATE TABLE IF NOT EXISTS admin_allowlist (
  user_id TEXT PRIMARY KEY,
  role TEXT NOT NULL CHECK (role = 'super_admin'),
  created_at TEXT NOT NULL,
  created_by TEXT,
  note TEXT
);

CREATE TABLE IF NOT EXISTS admin_audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  admin_user_id TEXT NOT NULL,
  action TEXT NOT NULL,
  resource_type TEXT,
  resource_id TEXT,
  reason TEXT,
  success INTEGER NOT NULL,
  correlation_id TEXT,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_audit_user_time ON admin_audit_log (admin_user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_admin_audit_action_time ON admin_audit_log (action, created_at);
