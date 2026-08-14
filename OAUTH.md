# OAuth on this MCP server: how it works

This server exposes an MCP endpoint at `/mcp` that MCP clients (Claude
Desktop, Claude.ai, etc.) authenticate to via OAuth. The implementation
lives in `src/oauth.ts`, with its schema in
`src/migrations/001_oauth.sql`. This doc explains what it does and why.

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

## What's stored, and what isn't

Authorization state lives in Supabase Postgres. The rule is: **anything a
client can't reconstruct on its own must survive a restart.**

| Table | Holds | Why it must persist |
|---|---|---|
| `oauth_clients` | `client_id`, `redirect_uris`, hashed registration access token | A client that registered last week must still resolve today, or every restart forces re-registration and a fresh consent prompt |
| `oauth_auth_requests` | In-flight consent pages | A restart mid-flow would otherwise strand the browser redirect |
| `oauth_auth_codes` | Authorization codes, hashed, single-use | Redeemed seconds after issue, but a restart in that window would break the exchange |
| `oauth_grants` | Standing consent per client | Lets a returning client skip the consent page; gives us something to revoke |
| `oauth_refresh_tokens` | Refresh tokens, hashed, rotated | The thing that keeps a client connected past the 1-hour access token |

Access tokens are deliberately *not* stored — they're stateless JWTs,
verified by signature. That's why `OAUTH_JWT_SECRET` must be stable: an
ephemeral per-boot secret invalidates every outstanding token on restart,
which defeats the point of persisting everything else.

Every token that lands in the database is stored as a SHA-256 hash, never
in the clear, so a read-only leak of the database yields nothing
replayable.

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
  "revocation_endpoint": "https://<our-domain>/revoke",
  "grant_types_supported": ["authorization_code", "refresh_token"],
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
its own freshly minted `client_id`, written to `oauth_clients` along with
its `redirect_uris`.

```json
{
  "client_id": "<uuid>",
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "redirect_uris": ["...whatever the caller sent..."],
  "registration_access_token": "<opaque secret, shown once>",
  "registration_client_uri": "https://<our-domain>/register/<client_id>"
}
```

### 3b. `GET`/`PUT`/`DELETE /register/:client_id` — client management

RFC 7592. A client can read, update, or delete its own registration by
presenting the `registration_access_token` it received above as a bearer
token. Only the token's hash is stored, and it's compared in constant
time. Deleting a registration cascades to that client's grants, codes,
and refresh tokens.

### 4. `GET /authorize` — the entire "login" step

Validates `client_id` against `oauth_clients`, checks `redirect_uri`
matches exactly, and requires PKCE (`code_challenge` +
`code_challenge_method: S256` — no PKCE, no request).

If the client already has an un-revoked row in `oauth_grants`, it's
already been approved: we skip the page entirely and redirect straight
back with a fresh code. **This is what makes a reconnect after a token
expiry silent instead of another prompt.** The code is issued for the
scope stored on the *grant*, not the scope in the query string, and a
client requesting anything beyond what it was granted falls through to the
consent page instead — otherwise a silent re-authorize would be a free
scope escalation. Otherwise we store the pending
request in `oauth_auth_requests` (10-minute expiry) and render a plain
HTML page:

```
Authorize access
An application is requesting access to this MCP server.
Client: <client name or id>
[ Approve ]  [ Reject ]
```

There is no username, password, or session check here. This page *is* the
consent screen and the authentication check, combined into one button.

### 5. `POST /authorize/decision`

Handles the button click. On **Approve**: records the grant under a
brand-new `grant_id`, replacing any previous one for that client. Reviving
the old id would leave a re-authorized session sharing a generation with
tokens from before the user disconnected — so one stale refresh token
could trip replay detection and take down the session they just approved.
It then mints a single-use authorization
code with a 60-second expiry, and redirects to the client's `redirect_uri`
with `?code=...&state=...`. On **Reject**: redirects with
`?error=access_denied` instead. Either way the pending request row is
deleted in the same statement that reads it, so it can't be replayed.

### 6. `POST /token`

Two grant types.

**`authorization_code`** — standard Authorization Code + PKCE exchange:

1. Claim the code by stamping `consumed_at`, in a single `UPDATE ...
   WHERE consumed_at IS NULL` — so two simultaneous redemptions can't both
   win. Unknown, expired, or already-used codes are rejected identically.
2. Confirm `client_id`/`redirect_uri` match what was authorized.
3. Recompute `SHA256(code_verifier)` and compare (in constant time) to the
   stored `code_challenge` — this is what stops a stolen authorization
   code from being redeemed by anyone other than whoever generated the
   original PKCE pair.
4. Confirm the grant still exists and isn't revoked.
5. Issue tokens.

**`refresh_token`** — exchanges a refresh token for a new access token,
**rotating** the refresh token in the process. The presented token is
claimed with the same single conditional `UPDATE` used for authorization
codes, so two concurrent refreshes can't both mint a valid chain.

If a token that was *already* rotated away is presented again, that's a
replay — it either leaked or the client is buggy. The grant itself and
every refresh token on it are revoked immediately, which forces a fresh
trip through the consent page. Revoking the *grant*, not just its tokens,
is the part that matters: leaving the grant alive would let the holder
walk straight back in through the silent re-approval path in step 4.

One exception, and it's the practical one: a rotated token re-presented
within a 30-second grace window (`REFRESH_REPLAY_GRACE_SECONDS`) is
declined with a plain `invalid_grant` and *no* revocation. Clients
genuinely do fire two refreshes at once, or retry a request whose response
they never saw; treating that as theft would disconnect well-behaved
clients for being slightly racy. Outside the window, it's a replay.

The response in both cases:

```json
{
  "access_token": "<JWT, 1 hour expiry>",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "<opaque, rotates on every use>",
  "scope": ""
}
```

Access tokens are short on purpose. A long-lived token is only tolerable
when there's no way to revoke it; now that refresh tokens and grants are
persisted, the short access token plus a revocable grant is strictly
better.

### 7. `POST /revoke`

RFC 7009. Revoking a refresh token also revokes the grant behind it and
every sibling token, so the client is fully disconnected rather than left
with a working access token until it happens to expire. Always returns
`200`, even for an unknown token, so a caller can't probe which tokens
exist.

The lookup matches on the token hash alone, deliberately ignoring whether
that token was already rotated. A client disconnecting after a refresh —
or sending a stale persisted copy — would otherwise get a `200` reading
"revoked" while the grant and all its live tokens kept working.

### 8. `POST /mcp` — verifying the token

Every `/mcp` request goes through `authenticateMcpRequest`, built with a
third-party `mcpAuth()` wrapper (`@clerk/mcp-tools/hono` — the helper
itself is generic, just a plain `(token) => AuthInfo | undefined`
callback, unrelated to any specific identity provider). Ours accepts
either:

- A static `MCP_AUTH_TOKEN` (env var) — the escape hatch for Claude
  Desktop's header-based config, which has no OAuth flow at all.
- A JWT signed by this server — verified against `OAUTH_JWT_SECRET`, and
  then checked against `oauth_grants`. That second check is what makes
  revocation take effect immediately rather than waiting out the token's
  remaining lifetime; it's the one place we trade a database round-trip
  for correctness.

The grant check **fails open**: if Postgres is unreachable, a request with
a valid signature is allowed through and the error is logged. A bad
signature is still a hard `401`. This is deliberate — clients read a `401`
on `/mcp` as "re-authorize", so failing closed would mean a few seconds of
database unavailability disconnects every client at once, which is the
exact failure this design exists to prevent. The cost is that a revocation
may not take effect during an outage.

## Required environment variables

From `.env.example`:

| Variable | Purpose |
|---|---|
| `DATABASE_URL` | Supabase Postgres, transaction pooler (port 6543). Required — the server creates its tables at boot and won't start without it. |
| `OAUTH_JWT_SECRET` | Signs/verifies access tokens. If unset, a random secret is generated at boot and all access tokens break on the next restart. |
| `MCP_AUTH_TOKEN` | Static bearer token accepted as an OAuth alternative (Claude Desktop) |

The pooler hands out a different backend connection per transaction, so
`postgres.js` is configured with `prepare: false` (see `src/db.ts`).
Without that you get intermittent "prepared statement does not exist"
errors under concurrency rather than a clean failure at boot.

Expired auth requests, codes, and long-dead refresh tokens are swept
hourly (`sweepExpired()`), so abandoned flows don't accumulate.

## What this intentionally doesn't do

There's still no real authentication and no way to know *who* approved a
request — the consent page is one button, and the `client_id` is the only
identity in the token. Grants and refresh tokens can be revoked, but
there's no UI for it; you'd do it with SQL or a `/revoke` call. Items are
still stored in memory (`src/items-store.ts`) and reset on every restart —
only the OAuth state is durable.

If knowing who's connecting becomes necessary, that's the point at which a
real identity provider (or at least a password on the consent page) is
worth reintroducing.
