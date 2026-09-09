# Creovah

A single-repo Node/Express app with a real marketing landing page, authentication, email verification, onboarding, and a protected starter workspace.

## Render

Build: `npm install`
Start: `npm start`
Health: `/api/health`

Environment variables:
- `JWT_SECRET`
- `MONGODB_URI`
- `MAILJET_API_KEY`
- `MAILJET_SECRET_KEY`
- `MAILJET_SENDER_EMAIL=creovah@gmail.com`
- `MAILJET_SENDER_NAME=creovah`

The social connection UI is intentionally a UI/state layer for now. Real Meta/TikTok OAuth credentials and platform review are separate integrations and should be added before claiming that accounts can actually publish.
