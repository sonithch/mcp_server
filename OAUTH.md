# OAuth on this MCP server: how it works

This server exposes an MCP endpoint at `/mcp` that MCP clients (Claude
Desktop, Claude.ai, etc.) authenticate to via OAuth. The implementation
lives in `src/oauth.ts`. This doc explains what it does and why.

## No external identity provider

This server is its own, complete OAuth 2.0 authorization server — there's
no external identity provider behind it. There's also no real user login:
`/authorize` renders a plain page with **Approve** and **Reject** buttons,
and clicking Approve *is* the entire authentication step. Whoever reaches
the server's URL can grant themselves access.

This is a deliberate simplification for a personal/low-stakes server. It
trades real identity and access control for having zero external
dependencies and zero moving parts to misconfigure. Don't reuse this
pattern for anything that needs to know *who* is authenticating, or that
needs to keep specific people out.

## The endpoints, in the order a client hits them

### 1. `GET /.well-known/oauth-protected-resource/mcp`

Per RFC 9728, the client's first move is asking "who's the authorization
server for this resource?" We answer with ourselves:

```json
{ "resource": "https://<our-domain>/mcp", "authorization_servers": ["https://<our-domain>"] }
```

### 2. `GET /.well-known/oauth-authorization-server`

Per RFC 8414, standard metadata describing our own endpoints:

```json
{
  "issuer": "https://<our-domain>",
  "authorization_endpoint": "https://<our-domain>/authorize",
  "token_endpoint": "https://<our-domain>/token",
  "registration_endpoint": "https://<our-domain>/register",
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"]
}
```

`token_endpoint_auth_methods_supported: ["none"]` signals a public-client
flow (PKCE, no client secret) — appropriate since every client here is a
public client and none can safely hold a secret.

Both this and the previous endpoint derive their own URL from
`X-Forwarded-Proto`/`X-Forwarded-Host` rather than the request's own
scheme (`getPublicOrigin()` in `oauth.ts`). Render terminates TLS at the
edge and forwards plain HTTP internally, so trusting the raw request URL
would advertise `http://` endpoints — which clients correctly refuse to
exchange a code against.

### 3. `POST /register` — real Dynamic Client Registration

Unlike a proxy in front of a DCR-less identity provider, we own the whole
authorization server, so registration is real (RFC 7591): each caller gets
its own freshly minted `client_id`, stored in memory alongside its
`redirect_uris`.

```json
{
  "client_id": "<uuid>",
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "redirect_uris": ["...whatever the caller sent..."]
}
```

### 4. `GET /authorize` — the entire "login" step

Validates `client_id` against what was registered, checks `redirect_uri`
matches exactly, requires PKCE (`code_challenge` + `code_challenge_method:
S256` — no PKCE, no request), and stores the pending request in memory
keyed by a random `request_id`. It then renders a plain HTML page:

```
Authorize access
An application is requesting access to this MCP server.
Client: <client_id>
[ Approve ]  [ Reject ]
```

There is no username, password, or session check here. This page *is* the
consent screen and the authentication check, combined into one button.

### 5. `POST /authorize/decision`

Handles the button click. On **Approve**: mints a single-use authorization
code (60-second expiry), and redirects to the client's `redirect_uri` with
`?code=...&state=...`. On **Reject**: redirects with `?error=access_denied`
instead. Either way, the pending request is deleted (single-use).

### 6. `POST /token`

Standard Authorization Code + PKCE exchange:

1. Look up the code; reject if unknown, expired, or already used (deleted
   on first use).
2. Confirm `client_id`/`redirect_uri` match what was authorized.
3. Recompute `SHA256(code_verifier)` and compare to the stored
   `code_challenge` — this is what stops a stolen authorization code from
   being redeemed by anyone other than whoever generated the original PKCE
   pair.
4. On success, sign and return our own access token:

```json
{
  "access_token": "<JWT, 30 day expiry>",
  "token_type": "Bearer",
  "expires_in": 2592000,
  "scope": ""
}
```

The token is a JWT signed with `OAUTH_JWT_SECRET` (or a random secret
generated at boot if unset — meaning every restart invalidates all
previously issued tokens). Its payload just carries the `client_id`; there's
no real user identity to carry, since none was ever established.

### 7. `POST /mcp` — verifying the token

Every `/mcp` request goes through `authenticateMcpRequest`, built with a
third-party `mcpAuth()` wrapper (`@clerk/mcp-tools/hono` — the helper
itself is generic, just a plain `(token) => AuthInfo | undefined`
callback, unrelated to any specific identity provider). Ours accepts
either:

- A static `MCP_AUTH_TOKEN` (env var) — the escape hatch for Claude
  Desktop's header-based config, which has no OAuth flow at all.
- A JWT signed by this server — verified against `OAUTH_JWT_SECRET`,
  nothing else to check.

## Required environment variables

From `.env.example`:

| Variable | Purpose |
|---|---|
| `MCP_AUTH_TOKEN` | Static bearer token accepted as an OAuth alternative (Claude Desktop) |
| `OAUTH_JWT_SECRET` | Signs/verifies our own access tokens. If unset, a random secret is generated at boot and all tokens become invalid on the next restart. |

## What this intentionally doesn't do

There's no real authentication, no way to know who approved a request, no
way to revoke a single token early (only rotating `OAUTH_JWT_SECRET`
invalidates everything at once), and no refresh tokens (access tokens are
just long-lived — 30 days — instead). If any of that becomes necessary,
that's the point at which a real identity provider (or at least a password
on the consent page) is worth reintroducing.
