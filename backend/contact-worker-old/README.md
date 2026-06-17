# 1Fin Contact Worker

A secure Cloudflare Workers backend for processing contact form submissions.

## Prerequisites

- Rust toolchain installed (`rustup`, `cargo`).
- Rust Worker build tool installed (`cargo install worker-build --version 0.8.5`).
- Cloudflare Wrangler available through `npx wrangler` or installed globally.
- Cloudflare account with Workers access.
- Resend account and API key.
- Cloudflare Turnstile keys.

## Local development

1. Create a local Wrangler variables file:

```bash
cp backend/contact-worker/.env.example backend/contact-worker/.dev.vars
```

2. Fill in the secrets in `backend/contact-worker/.dev.vars`.

`backend/contact-worker/.dev.vars` is ignored by git and is intended for local development only.

3. Run the Worker locally:

```bash
cd backend/contact-worker
npx wrangler dev --local --port 8787
```

The Worker listens locally and can be called from your static site.

With the default frontend config, local submissions are sent to:

```bash
http://127.0.0.1:8787/
```

## Turnstile keys

For local development, use the Cloudflare Turnstile test site key:

- Site key: `1x00000000000000000000AA`
- Secret key: `0x0000000000000000000000000000000000000000`

For production, create your own Turnstile site key and secret in the Cloudflare dashboard.

## Configuring Worker secrets

Use Wrangler to add secrets to the Cloudflare Worker environment:

```bash
cd backend/contact-worker
wrangler secret put TURNSTILE_SECRET_KEY
wrangler secret put RESEND_API_KEY
wrangler secret put CONTACT_RECIPIENT
wrangler secret put CONTACT_FROM_ADDRESS
wrangler secret put ALLOWED_ORIGINS
wrangler secret put EXPECTED_TURNSTILE_HOSTNAMES
```

`ALLOWED_ORIGINS` should contain the exact origins allowed to POST to the Worker, for example:

```
http://127.0.0.1:5500,http://localhost:5500,https://www.example.com
```

`EXPECTED_TURNSTILE_HOSTNAMES` should contain the hostnames where the Turnstile widget is served from, for example:

```
127.0.0.1,localhost,example.com
```

## Configuring Resend

1. Create a Resend account and API key.
2. Set `RESEND_API_KEY` as a Worker secret.
3. Set `CONTACT_RECIPIENT` to the advisor's destination email.
4. Set `CONTACT_FROM_ADDRESS` to a verified sender address for Resend.

## Allowed origins and CORS

The Worker will validate the `Origin` request header against `ALLOWED_ORIGINS`.
Only exactly matching origins are allowed.

## Manual deployment

Deploy manually with Wrangler:

```bash
cd backend/contact-worker
wrangler publish
```

If you need a specific route or account, update `backend/contact-worker/wrangler.toml` with `account_id`, `zone_id`, and route configuration.

## Testing submissions

### Successful submission

1. Serve the static site locally.
2. Fill the contact form.
3. Submit the form normally.
4. The backend verifies Turnstile, validates the request, and sends email through Resend.

### Rejected submission

The Worker rejects submissions when:

- required fields are missing,
- the honeypot field is filled,
- the form is submitted too quickly,
- the Turnstile token is invalid,
- the request origin is not allowed,
- unexpected fields are present.

Use the browser-facing error messages and check your Worker logs for generic failure reasons.
