import { OAuth2Client } from 'google-auth-library';
import { ApiError, requireValue } from '../core.js';

export type GoogleIdentityClaims = {
  subject: string;
  email: string;
  name: string;
  nonce: string;
};

export interface GoogleTokenVerifier {
  verify(credential: string, audience: string): Promise<GoogleIdentityClaims>;
}

export class GoogleIdentityVerifier implements GoogleTokenVerifier {
  private client = new OAuth2Client();

  async verify(credential: string, audience: string): Promise<GoogleIdentityClaims> {
    let payload;
    try {
      const ticket = await this.client.verifyIdToken({ idToken: credential, audience });
      payload = ticket.getPayload();
    } catch {
      throw new ApiError(401, 'Google sign-in could not be verified. Please try again.', 'INVALID_GOOGLE_CREDENTIAL');
    }

    requireValue(
      payload?.sub && payload.email && payload.email_verified === true && typeof payload.nonce === 'string' &&
        (payload.iss === 'accounts.google.com' || payload.iss === 'https://accounts.google.com'),
      401,
      'Google sign-in could not be verified. Please try again.',
      'INVALID_GOOGLE_CREDENTIAL',
    );
    const email = payload.email.trim().toLowerCase();
    requireValue(/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email), 401, 'Google sign-in could not be verified. Please try again.', 'INVALID_GOOGLE_CREDENTIAL');
    return {
      subject: payload.sub,
      email,
      name: (payload.name || email.split('@')[0]).trim().slice(0, 180),
      nonce: payload.nonce,
    };
  }
}
