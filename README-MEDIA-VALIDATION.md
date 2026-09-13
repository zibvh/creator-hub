# Creovah Media + Platform Validation

This build changes media handling so uploaded photos/videos are saved to Cloudinary and the saved media is reused for drafts, scheduled posts and publishing.

## Render environment variables
Add:

- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`

Do not put the Cloudinary API secret in frontend code.

## Publishing flow
1. User selects any connected platforms.
2. Media is uploaded once to Cloudinary.
3. Creovah validates the post against every selected platform before publishing/scheduling.
4. If a rule is violated, publishing/scheduling is stopped and the platform-specific reason is shown.
5. When valid, each platform receives media through its own API flow. Cloudinary is storage/source, not the social post itself.

## Current platform validation
- TikTok: media required; photos or one video, not mixed; up to 35 photos; TikTok scheduling blocked; photo/video size checks.
- X: 280-character text limit; up to 4 images or one video.
- LinkedIn: 3,000-character text limit; one media item in this build.
- Instagram: 2,200-character limit and media required; publishing is explicitly reported as not available until its publishing adapter is enabled.
- Facebook: text limit check; publishing is explicitly reported as not available until its publishing adapter is enabled.

The validator is centralized so additional social platforms can be added without tying the publishing flow to a particular pair of platforms.

## Important
Platform API failures are caught per platform. If one platform succeeds and another fails, Creovah reports the partial result instead of pretending everything succeeded.
