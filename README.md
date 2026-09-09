# Creovah

Single-repo full-stack app. Express serves `public/` and `/api/*`.

## Render
Build: `npm install`
Start: `npm start`
Health: `/api/health`

Environment variables:
- JWT_SECRET
- MONGODB_URI
- MAILJET_API_KEY
- MAILJET_SECRET_KEY
- MAILJET_SENDER_EMAIL
- MAILJET_SENDER_NAME

Mailjet is used for verification emails. `creovah@gmail.com` is the configured sender address; Mailjet may require sender verification before production sending.
