import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Config } from './config.js';
import type { Store, Row } from './db.js';
import type { GoogleIdentityClaims } from './services/google-identity.js';
import { equal, hash, token, now, id, passwordHash, checkPassword, requireValue } from './core.js';

export type Principal = { id: string; name: string; email: string; role: 'customer' | 'admin' };
export class Auth {
  constructor(private db: Store, private cfg: Config) {}
  current(req: FastifyRequest, role: Principal['role']): Principal | undefined {
    const raw = req.cookies[`aurie_${role}`];
    if (!raw) return;
    const row = this.db.one('SELECT p.id,p.name,p.email,p.role FROM sessions s JOIN principals p ON p.id=s.principal_id WHERE s.token_hash=? AND s.expires_at>? AND p.active=1 AND p.role=?', hash(raw), now(), role);
    return row as Principal | undefined;
  }
  need(req: FastifyRequest, role: Principal['role']): Principal {
    const person = this.current(req, role);
    requireValue(person, 401, `${role === 'admin' ? 'Admin' : 'Customer'} sign-in required.`, 'AUTH_REQUIRED');
    return person;
  }
  async register(name: string, email: string, password: string, role: Principal['role'] = 'customer') {
    const credential = await passwordHash(password);
    return this.registerWithPasswordHash(name, email, credential, role);
  }
  registerWithPasswordHash(name: string, email: string, credential: string, role: Principal['role'] = 'customer') {
    return this.db.tx(() => this.insertPrincipal(name, email, credential, role, true, true));
  }
  // Signup verification calls this while it consumes the matching code in the same transaction.
  createVerifiedCustomerInTransaction(name: string, email: string, credential: string) {
    return this.insertPrincipal(name, email, credential, 'customer', true, true);
  }
  private insertPrincipal(name: string, email: string, credential: string, role: Principal['role'], passwordEnabled: boolean, emailVerified: boolean) {
    const normalized = email.trim().toLowerCase();
    requireValue(!this.db.one('SELECT id FROM principals WHERE role=? AND email=?', role, normalized), 409, 'An account with this email already exists.', 'EMAIL_EXISTS');
    const person = { id: id(), name: name.trim(), email: normalized, role };
    requireValue(person.name, 400, 'Name is required.');
    this.db.run('INSERT INTO principals(id,role,name,email,password_hash,created_at,password_enabled,email_verified) VALUES (?,?,?,?,?,?,?,?)', person.id, role, person.name, person.email, credential, now(), passwordEnabled ? 1 : 0, emailVerified ? 1 : 0);
    if (role === 'customer') this.db.run('INSERT INTO shopping(customer_id) VALUES (?)', person.id);
    return person;
  }
  async login(email: string | undefined, password: string, role: Principal['role']) {
    // Password-only legacy admin login is supported only with exactly one active admin.
    let row: Row | undefined;
    if (email) row = this.db.one('SELECT * FROM principals WHERE role=? AND email=? AND active=1', role, email.trim().toLowerCase());
    else if (role === 'admin') { const rows = this.db.all("SELECT * FROM principals WHERE role='admin' AND active=1 LIMIT 2"); if (rows.length === 1) row = rows[0]; }
    const valid = await checkPassword(password, row?.password_enabled === 1 ? row.password_hash : 'scrypt$invalid$' + '0'.repeat(128));
    requireValue(row && row.password_enabled === 1 && valid, 401, 'Invalid sign-in credentials.', 'INVALID_CREDENTIALS');
    return { id: row.id, name: row.name, email: row.email, role } as Principal;
  }
  issueGoogleNonce(nonce: string) {
    const timestamp = now();
    this.db.tx(() => {
      this.db.run('DELETE FROM google_login_nonces WHERE expires_at<=?', timestamp);
      this.db.run('INSERT INTO google_login_nonces(nonce_hash,expires_at,created_at) VALUES (?,?,?)', hash(nonce), new Date(Date.now() + 5 * 60_000).toISOString(), timestamp);
    });
  }
  consumeGoogleNonce(cookieNonce: string | undefined, tokenNonce: string) {
    requireValue(cookieNonce && equal(cookieNonce, tokenNonce), 401, 'Google sign-in expired. Please try again.', 'GOOGLE_NONCE_INVALID');
    const result = this.db.run('DELETE FROM google_login_nonces WHERE nonce_hash=? AND expires_at>?', hash(cookieNonce), now());
    requireValue(result.changes === 1, 401, 'Google sign-in expired. Please try again.', 'GOOGLE_NONCE_INVALID');
  }
  async googleLogin(identity: GoogleIdentityClaims) {
    const normalized = identity.email.trim().toLowerCase();
    const mapped = this.db.one("SELECT p.id,p.name,p.email,p.role,p.active FROM auth_identities i JOIN principals p ON p.id=i.principal_id WHERE i.provider='google' AND i.subject=?", identity.subject);
    if (mapped) {
      requireValue(mapped.role === 'customer' && mapped.active === 1, 401, 'Google sign-in could not be completed.', 'GOOGLE_ACCOUNT_UNAVAILABLE');
      return { id: mapped.id, name: mapped.name, email: mapped.email, role: 'customer' } as Principal;
    }
    const existing = this.db.one("SELECT id FROM principals WHERE role='customer' AND email=? AND active=1", normalized);
    const disabledPasswordHash = existing ? undefined : await passwordHash(token());
    return this.db.tx(() => {
      const concurrent = this.db.one("SELECT p.id,p.name,p.email,p.role,p.active FROM auth_identities i JOIN principals p ON p.id=i.principal_id WHERE i.provider='google' AND i.subject=?", identity.subject);
      if (concurrent) {
        requireValue(concurrent.role === 'customer' && concurrent.active === 1, 401, 'Google sign-in could not be completed.', 'GOOGLE_ACCOUNT_UNAVAILABLE');
        return { id: concurrent.id, name: concurrent.name, email: concurrent.email, role: 'customer' } as Principal;
      }
      let customer = this.db.one("SELECT id,name,email,active,email_verified FROM principals WHERE role='customer' AND email=?", normalized);
      if (!customer) {
        const person = this.insertPrincipal(identity.name || normalized.split('@')[0], normalized, disabledPasswordHash!, 'customer', false, true);
        customer = { ...person, active: 1, email_verified: 1 };
      }
      requireValue(customer.active === 1 && customer.email_verified === 1, 401, 'Google sign-in could not be completed.', 'GOOGLE_ACCOUNT_UNAVAILABLE');
      requireValue(!this.db.one("SELECT principal_id FROM auth_identities WHERE provider='google' AND principal_id=?", customer.id), 409, 'A different Google account is already linked to this customer.', 'GOOGLE_ACCOUNT_ALREADY_LINKED');
      this.db.run("INSERT INTO auth_identities(provider,subject,principal_id,created_at) VALUES ('google',?,?,?)", identity.subject, customer.id, now());
      return { id: customer.id, name: customer.name, email: customer.email, role: 'customer' } as Principal;
    });
  }
  establish(req: FastifyRequest, reply: FastifyReply, person: Principal) {
    this.revoke(req, person.role);
    const raw = token();
    this.db.run('INSERT INTO sessions VALUES (?,?,?,?)', hash(raw), person.id, new Date(Date.now() + this.cfg.sessionHours * 3600000).toISOString(), now());
    reply.setCookie(`aurie_${person.role}`, raw, { path: '/', httpOnly: true, secure: this.cfg.secureCookie, sameSite: this.cfg.sameSite, maxAge: this.cfg.sessionHours * 3600 });
  }
  revoke(req: FastifyRequest, role: Principal['role']) {
    const raw = req.cookies[`aurie_${role}`];
    if (raw) this.db.run('DELETE FROM sessions WHERE token_hash=?', hash(raw));
  }
  logout(req: FastifyRequest, reply: FastifyReply, role: Principal['role']) {
    this.revoke(req, role);
    reply.clearCookie(`aurie_${role}`, { path: '/', httpOnly: true, secure: this.cfg.secureCookie, sameSite: this.cfg.sameSite });
    return { ok: true };
  }
}
