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


## Meta connections
Facebook and Instagram are separate connection flows. Configure the current Facebook Login for Business configuration in Render:

- `FB_CONFIG_ID=1528947972253797` — current Facebook Login for Business configuration.
- `INSTAGRAM_CONFIG_ID=` — leave empty until Instagram is configured separately.
- `FB_REDIRECT_URI=https://creovah.onrender.com/api/connections/facebook/callback`

The dashboard sends `/api/connections/facebook/start` for Facebook and `/api/connections/instagram/start` for Instagram. The callback uses a one-time server-side OAuth state to finish the correct connection without automatically connecting the other platform.


## Facebook Login for Business
The dashboard uses the Facebook JavaScript SDK Login Button with config_id `1528947972253797`. The SDK returns a one-time authorization code to the authenticated browser session; Creovah exchanges it server-side. Instagram remains a separate connection.
