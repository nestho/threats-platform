-- Subscription state for threats.top Pro.
--
-- Operational data only: it never enters git and never feeds the public JSON.
-- Timestamps are ISO-8601 UTC strings; rate-limit windows are epoch seconds.

CREATE TABLE settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

INSERT OR IGNORE INTO settings (key, value) VALUES
  ('pro_monthly_cents', '3900'),
  ('usdt_trc20_address', 'TAH1B9ksFekoqBmQaRbGqooca7MSUadvn2'),
  ('btc_address', 'bc1q6x9fek8970t38dvh7s4utt4ge47uhz3jl0etjq'),
  ('stix_rate_per_min', '600'),
  ('support_email', 'nestho@icloud.com'),
  ('order_retention_days', '180');

CREATE TABLE customers (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL COLLATE NOCASE UNIQUE,
  name TEXT NOT NULL,
  phone TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE TABLE orders (
  id TEXT PRIMARY KEY,
  code TEXT NOT NULL UNIQUE,
  customer_id TEXT NOT NULL REFERENCES customers(id),
  email TEXT NOT NULL COLLATE NOCASE,
  name TEXT NOT NULL,
  phone TEXT,
  plan TEXT NOT NULL DEFAULT 'pro',
  months INTEGER NOT NULL CHECK (months BETWEEN 1 AND 24),
  amount_cents INTEGER NOT NULL CHECK (amount_cents > 0),
  currency TEXT NOT NULL DEFAULT 'USD',
  method TEXT NOT NULL CHECK (method IN ('usdt_trc20', 'btc')),
  tx_ref TEXT NOT NULL,
  note TEXT,
  status TEXT NOT NULL CHECK (status IN ('pending', 'approved', 'rejected', 'expired')),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  reviewed_at TEXT,
  reviewed_by TEXT,
  review_note TEXT,
  ip_hash TEXT,
  user_agent_hash TEXT,
  UNIQUE (method, tx_ref)
);

CREATE INDEX orders_status_created ON orders (status, created_at DESC);
CREATE INDEX orders_email ON orders (email);
CREATE INDEX orders_customer ON orders (customer_id);

CREATE TABLE subscriptions (
  id TEXT PRIMARY KEY,
  customer_id TEXT NOT NULL REFERENCES customers(id),
  plan TEXT NOT NULL DEFAULT 'pro',
  status TEXT NOT NULL CHECK (status IN ('active', 'expired', 'revoked')),
  started_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  source_order_id TEXT REFERENCES orders(id),
  note TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX subscriptions_customer ON subscriptions (customer_id);
CREATE INDEX subscriptions_status_expires ON subscriptions (status, expires_at);

CREATE TABLE licenses (
  id TEXT PRIMARY KEY,
  subscription_id TEXT NOT NULL REFERENCES subscriptions(id),
  customer_id TEXT NOT NULL REFERENCES customers(id),
  key_hash TEXT NOT NULL UNIQUE,
  key_prefix TEXT NOT NULL,
  status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
  created_at TEXT NOT NULL,
  last_used_at TEXT,
  revoked_at TEXT
);

CREATE INDEX licenses_subscription ON licenses (subscription_id);

CREATE TABLE audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  actor TEXT NOT NULL,
  action TEXT NOT NULL,
  target TEXT NOT NULL,
  detail TEXT
);

CREATE INDEX audit_at ON audit_log (at DESC);

CREATE TABLE login_attempts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at TEXT NOT NULL,
  ip_hash TEXT NOT NULL,
  ok INTEGER NOT NULL CHECK (ok IN (0, 1))
);

CREATE INDEX login_attempts_ip_at ON login_attempts (ip_hash, at);

CREATE TABLE rate_limit (
  key TEXT NOT NULL,
  window_start INTEGER NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (key, window_start)
);
