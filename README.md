# CreatorHub — Phase 1 Full Stack

One repository. One Render Web Service. Express serves `public/` and `/api/*`.

## Current backend

- MongoDB persistence when `MONGODB_URI` is configured
- JSON fallback for local development
- Password hashing with bcrypt
- JWT sessions
- Registration
- Login endpoint
- Email verification with 10-minute hashed OTP
- Resend verification code
- Brevo transactional email support
- Onboarding persistence
- `/api/me`
- `/api/health`

## Local

```bash
npm install
cp .env.example .env
npm start
```

Open `http://localhost:10000`.

If Brevo is not configured, development mode prints the verification code in the server log and returns it to the frontend for testing.

## Render

Create a **Web Service** from this repo.

Build:
`npm install`

Start:
`npm start`

Health check:
`/api/health`

Add these environment variables in Render:

- `JWT_SECRET`
- `MONGODB_URI`
- `BREVO_API_KEY`
- `BREVO_SENDER_EMAIL`
- `BREVO_SENDER_NAME`

Never commit real secrets or `.env` to Git.

## Next

The next major feature is real OAuth for Instagram, Facebook and TikTok. The current social buttons only save onboarding preferences; they do not yet grant platform access or publish posts.

## UI icons

The interface uses Lucide icons rather than emoji glyphs for navigation, actions, status indicators and social connection controls.
