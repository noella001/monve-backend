# Customer authentication integration

Customer authentication uses the existing `aurie_customer` HttpOnly session cookie. Mutating requests must include `X-Aurie-Client: web` and use credentials so the browser sends and stores cookies.

## Email and password signup

Signup is now a two-step flow. The password is still required for later password login; the account and saved-shopping row are created only after the email code is verified.

1. Send `POST /api/account/signup` with `{ "name": "...", "email": "...", "password": "..." }`.
2. Show the code entry form. The response is `{ "message": "If this email can be registered, a verification code has been sent.", "verification_required": true, "expires_in": 600 }`. The response is deliberately generic. Codes expire after 10 minutes. Resend by submitting the signup form again; a 60-second cooldown and five-code daily limit apply per email.
3. Send `POST /api/account/signup/verify` with `{ "email": "...", "code": "123456" }`.
4. On success, the backend creates the customer and shopping record, sets `aurie_customer`, and returns the normal account payload: customer, cart, wishlist, `shopping_version`, issues, and orders.

The verification code is single-use. Five incorrect attempts invalidate it. Existing email/password login remains `POST /api/account/login` with `{ "email": "...", "password": "..." }`.

## Google sign-in

Google sign-in is for customer accounts only; it does not grant admin access. A Google-only account has no usable password and must continue using Google.

1. Send `POST /api/account/google/challenge` with `{}`. It sets a short-lived HttpOnly nonce cookie and returns `{ "client_id": "...", "nonce": "...", "expires_in": 300 }`.
2. Initialize Google Identity Services with the returned `client_id` and `nonce`. In the credential callback, send Google's ID-token `credential` to `POST /api/account/google` as `{ "credential": "..." }`.
3. On success, the backend verifies Google's token, consumes the nonce once, sets `aurie_customer`, and returns the normal account payload.

The Google challenge is one-use and expires after five minutes. Fetch a new challenge if it expires or sign-in is retried. Verified Google email can attach to an existing customer with the same email; Google accounts are matched on Google's stable subject identifier afterward.

## Shopping and session restore

After signup verification or sign-in, use the returned account payload and run the existing guest-shopping merge when guest items need to be preserved. On page load, `GET /api/account/session` restores the cookie session and saved cart/wishlist. Existing `PUT /api/account/shopping` and `POST /api/account/shopping/merge` contracts are unchanged.

## Server configuration

- Configure `BREVO_API_KEY` and `EMAIL_SENDER_EMAIL` to deliver signup codes.
- Set `AUTH_CODE_SECRET` to a random value of at least 32 characters in production. It protects stored code hashes and per-email rate-limit keys.
- Set `GOOGLE_CLIENT_ID` to a Google OAuth web client ID. The challenge endpoint returns this public client ID to the frontend. Configure the development and production website origins in Google Cloud and in `FRONTEND_ORIGINS`.
- Production cookies require HTTPS and the existing secure-cookie configuration. If the frontend and API are cross-site, configure `COOKIE_SAME_SITE=none` with `COOKIE_SECURE=true`.
