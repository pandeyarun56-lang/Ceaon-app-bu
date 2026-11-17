# CEAON

Home-services booking marketplace frontend and Node.js/Express backend.

## Project structure

- `public/index.html` — single-page web interface.
- `server.js` — Express API, OTP login, Google sign-in, partner onboarding, Cashfree payment primitives, bookings and chat.
- `package.json` / `package-lock.json` — Node dependencies and start script.
- `.env.example` — environment-variable names only.

## Run locally

1. Install Node.js 18 or newer.
2. Run `npm ci`.
3. Copy `.env.example` to `.env`.
4. Set a long, unique `JWT_SECRET`.
5. Run `npm start` and open `http://localhost:3000`.

## Render deployment

- Build command: `npm ci`
- Start command: `npm start`
- Runtime: Node
- Root directory: the folder containing `package.json` (if the repository contains a top-level `ceaon/` folder, set Root Directory to `ceaon`; if the files are at repository root, leave it blank).
- Add secrets in Render's Environment settings. Do not commit `.env`.

At minimum set `JWT_SECRET` and `NODE_ENV=production`. Add provider credentials only after creating and testing those provider accounts.

## Important limitations — not ready for real customers

This ZIP is a development baseline, not a production-ready marketplace. The following items still need implementation and end-to-end testing:

- Persistent database: users, bookings and payments are currently JSON files beside the server. Render's free instance filesystem is ephemeral; records can be lost on restart/redeploy. Use managed PostgreSQL before production.
- Partner live presence and GPS matching are partly held in process memory and the browser's local storage. They are not reliable across devices or server restarts.
- The UI still contains wallet top-up and home-visit-charge flows for which the server has no matching API routes.
- Booking creation, cancellation, partner accept/reject and the frontend's local booking state are not fully synchronized with the backend.
- Cashfree order creation/verification exists on the server, but the browser payment UI has legacy Razorpay code. Do not accept real payments until this is reconciled and tested.
- Scheduled bookings are currently client-side only.
- Aadhaar/PAN verification requires a properly enabled Cashfree Verification Suite account, valid credentials, compliant consent/privacy handling and provider-side testing.
- OTP delivery requires Twilio and/or SMTP credentials. Without them, codes are logged to server output, which is development-only.
- Google sign-in requires a configured OAuth client and authorized origins.
- Admin review, operational tooling, refund reconciliation, payout reconciliation, privacy policy, terms, security review and backups are not complete.

## Security

- Never commit `.env`, API keys, payment secrets, Aadhaar/PAN data or customer records.
- Keep the GitHub repository private while developing.
- Do not use real customer data or enable production payment/KYC credentials until the unfinished items above are addressed.
