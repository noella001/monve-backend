ALTER TABLE principals ADD COLUMN password_enabled INTEGER NOT NULL DEFAULT 1 CHECK(password_enabled IN (0,1));
ALTER TABLE principals ADD COLUMN email_verified INTEGER NOT NULL DEFAULT 1 CHECK(email_verified IN (0,1));

CREATE TABLE signup_verifications (
 email TEXT PRIMARY KEY COLLATE NOCASE,
 name TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 code_hash TEXT NOT NULL,
 attempts INTEGER NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 5),
 expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX signup_verifications_expiry ON signup_verifications(expires_at);

CREATE TABLE signup_code_limits (
 email_hash TEXT PRIMARY KEY,
 window_started_at TEXT NOT NULL,
 last_sent_at TEXT NOT NULL,
 send_count INTEGER NOT NULL CHECK(send_count > 0)
);

CREATE TABLE auth_identities (
 provider TEXT NOT NULL CHECK(provider IN ('google')),
 subject TEXT NOT NULL,
 principal_id TEXT NOT NULL REFERENCES principals(id) ON DELETE CASCADE,
 created_at TEXT NOT NULL,
 PRIMARY KEY(provider,subject),
 UNIQUE(provider,principal_id)
);
CREATE INDEX auth_identities_owner ON auth_identities(principal_id);

CREATE TABLE google_login_nonces (
 nonce_hash TEXT PRIMARY KEY,
 expires_at TEXT NOT NULL,
 created_at TEXT NOT NULL
);
CREATE INDEX google_login_nonces_expiry ON google_login_nonces(expires_at);
