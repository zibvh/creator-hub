# CreatorHub Phase 1

This is the rebuilt Phase 1 frontend extracted into a maintainable folder structure.

## Folder

```text
creator-hub/
└── phase-1/
    ├── index.html
    ├── css/
    │   └── styles.css
    ├── js/
    │   └── app.js
    └── README.md
```

## Phase 1 scope

- Dashboard
- Create Post
- Platform selection
- Publish now flow
- Schedule flow
- Scheduled queue
- Published history
- Failed posts
- Connected accounts
- Responsive mobile UI

## Important

The current UI is intentionally frontend-only. Posts are held in JavaScript state for the MVP workflow. Real authentication, database persistence, OAuth connections and platform publishing should be connected in Phase 2.

## Onboarding

Open `onboarding/index.html` to test the new onboarding flow:

1. Account details — email, username, name, phone
2. Email verification UI
3. Role + discovery source
4. Instagram / Facebook / TikTok connections
5. Browser push notification permission
6. Completion / dashboard handoff

Social connections are currently UI-only until OAuth credentials and backend endpoints are wired.
