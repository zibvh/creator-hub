# Creovah v20 — LinkedIn edit media fix

This build improves the LinkedIn Edit flow.

## Changes
- Edit now loads the existing LinkedIn image/video into the composer preview when LinkedIn exposes the media download URL.
- Edit can change the caption/title.
- Selecting a new photo/video while editing replaces the media on LinkedIn by creating the corrected post and removing the old post.
- Removing existing media creates a text-only replacement and removes the old media post.
- Alt-text changes are handled through the same replacement flow when an existing media post is edited.
- Existing text-only edits continue to use LinkedIn's partial-update API.
- Drafts can still be continued without publishing.

## Important
LinkedIn's Posts API does not expose a direct media-replacement field in partial updates. Media changes therefore use a replacement-post flow. The replacement is created first so the old post is not removed if the new version cannot be created.

Existing media preview uses LinkedIn's media download URL. Those URLs are temporary/signed and are fetched again when Edit is opened.
