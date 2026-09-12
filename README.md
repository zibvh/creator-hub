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

The Meta Facebook connection is wired to the server-side Login for Business OAuth flow. TikTok remains separate and unconfigured.


## Meta connections
Facebook and Instagram are separate connection flows. Configure the current Facebook Login for Business configuration in Render:

- `FB_CONFIG_ID=1528947972253797` — current Facebook Login for Business configuration.
- `INSTAGRAM_CONFIG_ID=` — leave empty until Instagram is configured separately.
- `FB_REDIRECT_URI=https://creovah.onrender.com/api/connections/facebook/callback`

The dashboard sends `/api/connections/facebook/start` for Facebook. The production callback is hardcoded to `https://creovah.onrender.com/api/connections/facebook/callback` so a stale Render environment variable cannot create a redirect mismatch. The callback uses a one-time server-side OAuth state to finish the correct connection without automatically connecting Instagram.


## Facebook Login for Business
Facebook uses the server-side Login for Business redirect flow with config_id `1528947972253797` and a server-side code exchange. Instagram remains a separate connection and is not invoked by the Facebook button.
