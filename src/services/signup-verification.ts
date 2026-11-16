import { createHmac, randomInt } from 'node:crypto';
import type { Config } from '../config.js';
import type { Store } from '../db.js';
import { ApiError, equal, hash, now, passwordHash, requireValue } from '../core.js';
import { Auth, type Principal } from '../auth.js';
import { Emails } from './emails.js';

const CODE_TTL_MS = 10 * 60_000;
const EMAIL_COOLDOWN_MS = 60_000;
const EMAIL_WINDOW_MS = 24 * 60 * 60_000;
const EMAIL_SEND_LIMIT = 5;
const CODE_ATTEMPT_LIMIT = 5;

export class SignupVerification {
  constructor(private db: Store, private cfg: Config, private auth: Auth, private emails: Emails) {}

  cleanup() {
    const timestamp = now();
    this.db.run('DELETE FROM signup_verifications WHERE expires_at<=?', timestamp);
    this.db.run('DELETE FROM signup_code_limits WHERE window_started_at<=?', new Date(Date.now() - EMAIL_WINDOW_MS).toISOString());
  }

  async request(name: string, email: string, password: string) {
    this.requireReady();
    const normalized = email.trim().toLowerCase();
    const credential = await passwordHash(password);
    const code = String(randomInt(0, 1_000_000)).padStart(6, '0');
    const codeHash = this.codeHash(normalized, code);
    const emailHash = this.emailHash(normalized);
    const timestamp = now();
    const expiresAt = new Date(Date.now() + CODE_TTL_MS).toISOString();

    const shouldSend = this.db.tx(() => {
      this.cleanup();
      if (this.db.one("SELECT id FROM principals WHERE role='customer' AND email=?", normalized)) return false;

      const limits = this.db.one('SELECT * FROM signup_code_limits WHERE email_hash=?', emailHash);
      const inWindow = Boolean(limits && Date.now() - Date.parse(limits.window_started_at) < EMAIL_WINDOW_MS);
      if (limits && Date.now() - Date.parse(limits.last_sent_at) < EMAIL_COOLDOWN_MS) return false;
      if (limits && inWindow && limits.send_count >= EMAIL_SEND_LIMIT) return false;

      if (!inWindow || !limits) {
        this.db.run('INSERT INTO signup_code_limits(email_hash,window_started_at,last_sent_at,send_count) VALUES (?,?,?,1) ON CONFLICT(email_hash) DO UPDATE SET window_started_at=excluded.window_started_at,last_sent_at=excluded.last_sent_at,send_count=1', emailHash, timestamp, timestamp);
      } else {
        this.db.run('UPDATE signup_code_limits SET last_sent_at=?,send_count=send_count+1 WHERE email_hash=?', timestamp, emailHash);
      }
      this.db.run(
        `INSERT INTO signup_verifications(email,name,password_hash,code_hash,attempts,expires_at,created_at)
         VALUES (?,?,?,?,0,?,?) ON CONFLICT(email) DO UPDATE SET name=excluded.name,password_hash=excluded.password_hash,
         code_hash=excluded.code_hash,attempts=0,expires_at=excluded.expires_at,created_at=excluded.created_at`,
        normalized, name.trim(), credential, codeHash, expiresAt, timestamp,
      );
      return true;
    });

    if (shouldSend) {
      try {
        await this.emails.sendSignupVerification(normalized, code);
      } catch (error) {
        if (error instanceof ApiError && error.code === 'EMAIL_DELIVERY_FAILED') {
          this.db.run('DELETE FROM signup_verifications WHERE email=? AND code_hash=?', normalized, codeHash);
        }
        throw error;
      }
    }
    return { message: 'If this email can be registered, a verification code has been sent.', verification_required: true, expires_in: CODE_TTL_MS / 1000 };
  }

  verify(email: string, code: string): Principal {
    this.requireReady();
    const normalized = email.trim().toLowerCase();
    const result = this.db.tx(() => {
      const challenge = this.db.one('SELECT * FROM signup_verifications WHERE email=?', normalized);
      if (!challenge || challenge.expires_at <= now()) {
        if (challenge) this.db.run('DELETE FROM signup_verifications WHERE email=?', normalized);
        return undefined;
      }
      if (challenge.attempts >= CODE_ATTEMPT_LIMIT || !equal(this.codeHash(normalized, code), challenge.code_hash)) {
        const attempts = challenge.attempts + 1;
        if (attempts >= CODE_ATTEMPT_LIMIT) this.db.run('DELETE FROM signup_verifications WHERE email=?', normalized);
        else this.db.run('UPDATE signup_verifications SET attempts=? WHERE email=?', attempts, normalized);
        return undefined;
      }
      if (this.db.one("SELECT id FROM principals WHERE role='customer' AND email=?", normalized)) {
        this.db.run('DELETE FROM signup_verifications WHERE email=?', normalized);
        return undefined;
      }
      const person = this.auth.createVerifiedCustomerInTransaction(challenge.name, normalized, challenge.password_hash);
      this.db.run('DELETE FROM signup_verifications WHERE email=?', normalized);
      this.db.run('DELETE FROM signup_code_limits WHERE email_hash=?', this.emailHash(normalized));
      return person;
    });
    requireValue(result, 400, 'The verification code is invalid or expired. Request a new code and try again.', 'INVALID_SIGNUP_CODE');
    return result;
  }

  private requireReady() {
    requireValue(this.cfg.authCodeSecret.length >= 32, 503, 'Signup email verification is not configured on the server.', 'EMAIL_VERIFICATION_NOT_CONFIGURED');
    requireValue(this.emails.status().configured, 503, 'Signup email verification is not configured on the server.', 'EMAIL_VERIFICATION_NOT_CONFIGURED');
  }

  private codeHash(email: string, code: string) {
    return createHmac('sha256', this.cfg.authCodeSecret).update(`${email}\0${code}`).digest('hex');
  }

  private emailHash(email: string) {
    return createHmac('sha256', this.cfg.authCodeSecret).update(`signup-email\0${email}`).digest('hex');
  }
}
