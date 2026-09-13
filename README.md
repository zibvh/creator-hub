# Creovah v20 — X integration

This build adds X as a connected publishing platform alongside LinkedIn.

## X setup on Render
Add these environment variables:

- `X_CLIENT_ID` — X OAuth 2.0 Client ID
- `X_CLIENT_SECRET` — X OAuth 2.0 Client Secret (keep private)
- `X_REDIRECT_URI=https://creovah.onrender.com/api/connections/x/callback`

In the X Developer Console, enable OAuth 2.0 and add this exact callback URL.

Requested user scopes:
`tweet.read tweet.write users.read media.write offline.access`

Creovah uses OAuth 2.0 Authorization Code with PKCE, refresh tokens, X API v2 posts, and X media upload.

## X publishing
- Connect X from Settings.
- X appears in the connected-platform list.
- Publish now and save draft are available in the normal flow.
- Scheduling uses Creovah's scheduler.
- Scheduled X posts can be edited before they are published.
- Published X posts can be edited only within X's 30-minute edit window.
- Media is uploaded to X before publishing/scheduling.

## Current media behavior
- Images: JPG, PNG, GIF and WEBP, up to 5 MB.
- Videos: MP4/QuickTime/WebM through X's chunked upload flow.
- When adding media, select either LinkedIn or X rather than both in the same post.


## TikTok publishing

TikTok uses Login Kit + Content Posting API. Add these Render environment variables:
- `TIKTOK_CLIENT_KEY`
- `TIKTOK_CLIENT_SECRET`
- `TIKTOK_REDIRECT_URI=https://creovah.onrender.com/api/connections/tiktok/callback`

The TikTok app must have Login Kit and Content Posting API configured, with `user.info.basic` and `video.publish` approved. Direct publishing currently accepts video files (MP4/MOV/WEBM). TikTok posts require media. TikTok scheduling is intentionally blocked until Creovah has persistent media storage for future scheduled posts.
