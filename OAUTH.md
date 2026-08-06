# OAuth on this MCP server: how it works

This server exposes an MCP endpoint at `/mcp` that MCP clients (Claude
Desktop, Claude.ai, etc.) authenticate to via OAuth. The implementation is
split across `src/auth.ts` (the authorization server + identity engine)
and `src/oauth.ts` (the thin layer exposing it at the paths an MCP client
expects). This doc explains what it does and why.

## better-auth, not an external identity SaaS

This server is its own OAuth 2.0 / OIDC authorization server, using
[better-auth](https://better-auth.com) - a self-hosted, open-source
TypeScript library - rather than a hosted identity provider. Users sign in
with **Google**; better-auth handles the Google OAuth mechanics, and owns
its own local SQLite database of users, sessions, registered OAuth
clients, and access tokens. There's no external account portal, no
separate dashboard to misconfigure, no dev/production instance split.

(Two earlier iterations of this server used Clerk as the identity
provider, then a stateless anonymous Approve/Reject page with no identity
at all - see git history around `src/oauth.ts` for why each was replaced.
Clerk's development-instance cookie-sync "handshake" mechanism, needed
because a dev instance has no stable custom domain, turned out to interact
badly with this server's redirect-based OAuth proxy in ways that were hard
to diagnose and never fully resolved.)

## The endpoints, in the order a client hits them

### 1. `GET /.well-known/oauth-protected-resource/mcp` and `GET /.well-known/oauth-authorization-server`

Hand-written in `oauth.ts` (RFC 9728 and RFC 8414 respectively), deriving
the origin from `X-Forwarded-Proto`/`X-Forwarded-Host` rather than the
request's own URL - Render terminates TLS at the edge and forwards plain
HTTP internally, so trusting the raw request URL would advertise `http://`
endpoints that clients correctly refuse to use for a token exchange.

`authorization_endpoint` and `token_endpoint` point directly at
better-auth's real routes (`/api/auth/mcp/authorize`, `/api/auth/mcp/token`);
`registration_endpoint` points at our own `/register` (see below).

### 2. `POST /register`

better-auth's real Dynamic Client Registration endpoint
(`/api/auth/mcp/register`) has two rough edges for real MCP clients:
it requires `client_name` (a NOT-NULL database column) and defaults
`token_endpoint_auth_method` to `client_secret_basic` (a confidential
client) if omitted. Claude.ai's actual registration request sends neither
field - it expects a nameless, secret-less public client. `oauth.ts`'s
`/register` fills in both defaults (`client_name: "MCP Client"`,
`token_endpoint_auth_method: "none"`) before forwarding to the real
endpoint, so every caller gets a public, PKCE-only client without having
to ask for one explicitly.

### 3. `GET /authorize` — proxied straight through

Forwards the query string as-is to `/api/auth/mcp/authorize`. From here,
better-auth's own logic takes over:

- **No session yet** → redirects to our `loginPage` (`/authorize/login`),
  preserving every original query param so they survive the round trip.
- **`prompt=consent` in the request** (which is what Claude.ai actually
  sends) → redirects to our `consentPage` (`/authorize/consent`) instead.
- **Otherwise** → issues the authorization code immediately.

### 4. `GET /authorize/login`

Our own page: a single "Sign in with Google" button. Clicking it calls
better-auth's `/api/auth/sign-in/social` with `provider: "google"` and a
`callbackURL` of `/authorize?<original query>`, which returns a real
Google OAuth URL (`accounts.google.com/o/oauth2/v2/auth`, with its own PKCE
pair) to redirect the browser to. This is the one unavoidable browser hop
in the whole flow - Google requires interactive login, there's no
backend-only way to verify a Google identity.

After the user authenticates with Google, Google redirects to
`/api/auth/callback/google` (better-auth's callback, which must be
registered as an authorized redirect URI in Google Cloud Console).
better-auth creates the session and redirects back to the original
`/authorize?...` URL from `callbackURL` - now with a session, so step 3's
logic proceeds to the consent check.

### 5. `GET /authorize/consent`

Our own Approve/Reject page. better-auth redirects here with
`consent_code`, `client_id`, and `scope` as query params. Approve and
Reject both `POST` to better-auth's real `/api/auth/oauth2/consent` with
`{ accept, consent_code }`, which returns `{ redirectURI }` as JSON (not
an HTTP redirect) - a few lines of inline JS just follow it. On accept,
that URI is the client's `redirect_uri` with a real authorization code; on
reject, it's the same URL with `error=access_denied`.

### 6. `POST /api/auth/mcp/token` (mounted directly, no wrapper needed)

Standard Authorization Code + PKCE exchange, entirely handled by
better-auth: validates the code, confirms the PKCE `code_verifier` against
the stored `code_challenge`, and returns an access token plus (since the
default scopes include `openid`) an `id_token` carrying the user's real
Google-verified name and email.

### 7. `POST /mcp` — verifying the token

`authenticateMcpRequest` (built with `@clerk/mcp-tools/hono`'s `mcpAuth()`
wrapper - generic despite the package name, just a plain token-verify
callback) accepts either:

- A static `MCP_AUTH_TOKEN` (env var) - the escape hatch for Claude
  Desktop's header-based config, which has no OAuth flow at all.
- A real better-auth access token - verified via `auth.api.getMcpSession()`,
  which returns the associated `userId`/`clientId`/`scopes` for
  `createMcpServer`'s tools to use (e.g. `createdBy`/`updatedBy` tracking).

## Required environment variables

From `.env.example`:

| Variable | Purpose |
|---|---|
| `PUBLIC_URL` | Exact externally-reachable origin (scheme included). better-auth needs this as a fixed value up front - unlike our own routes, it can't infer it per-request. |
| `MCP_AUTH_TOKEN` | Static bearer token accepted as an OAuth alternative (Claude Desktop) |
| `BETTER_AUTH_SECRET` | Signs better-auth's session cookies and internal tokens |
| `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` | From Google Cloud Console; authorized redirect URI must be exactly `${PUBLIC_URL}/api/auth/callback/google` |
| `AUTH_DB_PATH` | SQLite file storing users/sessions/clients/tokens (default `./data/auth.db`) |

**Important**: on Render's free tier the filesystem is ephemeral - the
SQLite file is wiped on every deploy/restart, meaning every registered
client and every logged-in session is lost each time. Attach a persistent
disk, or point `database` in `src/auth.ts` at a managed Postgres/MySQL
instance instead (better-auth supports both via the same config option),
if that's not acceptable.

## What's genuinely ours vs. better-auth's

`src/auth.ts` configures better-auth (Google provider, the `mcp` plugin,
`loginPage`/`consentPage` routes) and runs its migrations at boot.
`src/oauth.ts` is the thin layer: the two hand-written `.well-known`
documents (needed because better-auth's own metadata endpoints are mounted
under `/api/auth/`, not at the root paths MCP clients expect), the
`/register` defaulting shim, and our own login/consent page HTML. Every
actual OAuth mechanic - DCR, PKCE, code issuance, token issuance, session
management, Google's OAuth dance - is better-auth's, not hand-rolled.
