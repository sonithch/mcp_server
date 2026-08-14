import { Hono } from "hono";
import { randomUUID, createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { mcpAuth, streamableHttpHandler } from "@clerk/mcp-tools/hono";
import { createMcpServer } from "./mcp-server.js";
import { sql, hashToken, newSecret } from "./db.js";

// This server is its own, self-contained OAuth 2.0 authorization server -
// no external identity provider. There's no real user login: /authorize
// renders a plain Approve/Reject page, and clicking Approve is the entire
// "authentication" step. This trades real identity for simplicity; anyone
// who reaches the server URL can grant themselves access. Fine for a
// personal/low-stakes MCP server, not something to reuse for anything that
// needs real access control.
//
// Durable state lives in Postgres (see src/migrations/001_oauth.sql).
// Access tokens are stateless JWTs and are not stored; client
// registrations, grants, and refresh tokens are, so that a restart or a
// cold start is invisible to an already-connected client.

const mcpAuthToken = process.env.MCP_AUTH_TOKEN;

const ACCESS_TOKEN_TTL_SECONDS = 60 * 60; // 1h - short, because refresh tokens now exist
const REFRESH_TOKEN_TTL_DAYS = 90;
const AUTH_CODE_TTL_SECONDS = 60;
const AUTH_REQUEST_TTL_SECONDS = 10 * 60; // how long the consent page stays valid
// How long after rotation a re-presented refresh token is treated as a
// benign retry rather than a stolen-token replay. See the /token handler.
const REFRESH_REPLAY_GRACE_SECONDS = 30;

// Signs/verifies our own access tokens. Falls back to a random secret
// generated at boot if none is set - tokens then just stop working across
// restarts, which now also defeats the point of the refresh tokens we
// persist, so set OAUTH_JWT_SECRET in production.
const jwtSecret = new TextEncoder().encode(process.env.OAUTH_JWT_SECRET ?? randomBytes(32).toString("hex"));
if (!process.env.OAUTH_JWT_SECRET) {
  console.warn("[oauth] OAUTH_JWT_SECRET not set - using an ephemeral secret; access tokens won't survive a restart");
}

// Render (and most PaaS providers) terminate TLS at the edge and forward
// plain HTTP internally, so c.req.url's own scheme is always "http" even
// though the real, public-facing request was https. Self-advertising
// "http://" endpoints breaks clients that (correctly) refuse to exchange a
// code for tokens over an unencrypted URL. Trust the proxy's forwarded
// headers over the request's own URL.
function getPublicOrigin(c: { req: { url: string; header: (name: string) => string | undefined } }): string {
  const url = new URL(c.req.url);
  const proto = c.req.header("x-forwarded-proto")?.split(",")[0]?.trim() ?? url.protocol.replace(":", "");
  const host = c.req.header("x-forwarded-host")?.split(",")[0]?.trim() ?? url.host;
  return `${proto}://${host}`;
}

// client_id and request_id are uuid columns; a malformed value would make
// Postgres throw rather than simply not match, turning a bad request into
// a 500. Filter them out before they reach a query.
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function isUuid(value: string | undefined): value is string {
  return !!value && UUID_RE.test(value);
}

function constantTimeEquals(a: string, b: string): boolean {
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  return timingSafeEqual(bufA, bufB);
}

export const oauth = new Hono();

oauth.get("/.well-known/oauth-protected-resource/mcp", (c) => {
  const origin = getPublicOrigin(c);
  return c.json({
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
  });
});

oauth.get("/.well-known/oauth-authorization-server", (c) => {
  const origin = getPublicOrigin(c);
  return c.json({
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    revocation_endpoint: `${origin}/revoke`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    revocation_endpoint_auth_methods_supported: ["none"],
    subject_types_supported: ["public"],
  });
});

// Dynamic Client Registration (RFC 7591). The registration is a row in
// Postgres, so a client_id issued today still resolves after a restart -
// which is the whole reason a client doesn't have to re-register and
// re-prompt the user every time the service cold-starts.
oauth.post("/register", async (c) => {
  const body = await c.req
    .json<{ redirect_uris?: string[]; client_name?: string }>()
    .catch((): { redirect_uris?: string[]; client_name?: string } => ({}));
  const redirectUris = body.redirect_uris ?? [];
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return c.json(
      { error: "invalid_client_metadata", error_description: "redirect_uris is required and must be an array" },
      400
    );
  }
  if (!redirectUris.every((uri) => URL.canParse(uri))) {
    return c.json({ error: "invalid_redirect_uri", error_description: "redirect_uris must be absolute URIs" }, 400);
  }

  const clientId = randomUUID();
  const registrationToken = newSecret();
  await sql`
    insert into oauth_clients (client_id, client_name, redirect_uris, registration_access_token_hash)
    values (${clientId}, ${body.client_name ?? null}, ${redirectUris}, ${hashToken(registrationToken)})
  `;

  const origin = getPublicOrigin(c);
  return c.json(
    {
      client_id: clientId,
      client_name: body.client_name,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: redirectUris,
      registration_access_token: registrationToken,
      registration_client_uri: `${origin}/register/${clientId}`,
    },
    201
  );
});

// RFC 7592 client management. Lets a client read, update, or delete its own
// registration using the token it got at registration time.
async function authenticateRegistration(clientId: string, authHeader: string | undefined) {
  const token = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
  if (!token || !isUuid(clientId)) return undefined;
  const [client] = await sql`
    select client_id, client_name, redirect_uris, registration_access_token_hash
    from oauth_clients where client_id = ${clientId}
  `;
  if (!client) return undefined;
  if (!constantTimeEquals(hashToken(token), client.registration_access_token_hash)) return undefined;
  return client;
}

oauth.get("/register/:client_id", async (c) => {
  const clientId = c.req.param("client_id");
  const client = await authenticateRegistration(clientId, c.req.header("authorization"));
  if (!client) return c.json({ error: "invalid_token" }, 401);
  return c.json({
    client_id: client.client_id,
    client_name: client.client_name,
    redirect_uris: client.redirect_uris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
});

oauth.put("/register/:client_id", async (c) => {
  const clientId = c.req.param("client_id");
  const client = await authenticateRegistration(clientId, c.req.header("authorization"));
  if (!client) return c.json({ error: "invalid_token" }, 401);

  const body = await c.req
    .json<{ redirect_uris?: string[]; client_name?: string }>()
    .catch((): { redirect_uris?: string[]; client_name?: string } => ({}));
  const redirectUris = body.redirect_uris ?? client.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0 || !redirectUris.every((uri: string) => URL.canParse(uri))) {
    return c.json({ error: "invalid_redirect_uri" }, 400);
  }

  await sql`
    update oauth_clients
    set redirect_uris = ${redirectUris}, client_name = ${body.client_name ?? client.client_name}
    where client_id = ${clientId}
  `;
  return c.json({
    client_id: clientId,
    client_name: body.client_name ?? client.client_name,
    redirect_uris: redirectUris,
    token_endpoint_auth_method: "none",
    grant_types: ["authorization_code", "refresh_token"],
    response_types: ["code"],
  });
});

oauth.delete("/register/:client_id", async (c) => {
  const clientId = c.req.param("client_id");
  const client = await authenticateRegistration(clientId, c.req.header("authorization"));
  if (!client) return c.json({ error: "invalid_token" }, 401);
  // Cascades to that client's grants, codes, and refresh tokens.
  await sql`delete from oauth_clients where client_id = ${clientId}`;
  return c.body(null, 204);
});

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}

async function issueCode(params: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
}): Promise<string> {
  const code = newSecret();
  await sql`
    insert into oauth_auth_codes (code_hash, client_id, redirect_uri, code_challenge, scope, expires_at)
    values (
      ${hashToken(code)}, ${params.clientId}, ${params.redirectUri},
      ${params.codeChallenge}, ${params.scope},
      now() + ${`${AUTH_CODE_TTL_SECONDS} seconds`}::interval
    )
  `;
  return code;
}

// No real login - this page IS the entire authentication step. Approve
// mints an authorization code for whoever clicked it; Reject sends the
// client an access_denied error. See the module-level comment for why.
oauth.get("/authorize", async (c) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope } =
    c.req.query();

  const [client] = isUuid(client_id)
    ? await sql`select client_id, client_name, redirect_uris from oauth_clients where client_id = ${client_id}`
    : [];
  if (!client) return c.json({ error: "invalid_client" }, 400);
  if (!redirect_uri || !client.redirect_uris.includes(redirect_uri)) {
    return c.json({ error: "invalid_request", error_description: "redirect_uri does not match registration" }, 400);
  }
  if (response_type !== "code") return c.json({ error: "unsupported_response_type" }, 400);
  if (!code_challenge || code_challenge_method !== "S256") {
    return c.json({ error: "invalid_request", error_description: "PKCE (S256) is required" }, 400);
  }

  // Already consented? Skip the page entirely - this is what makes a
  // reconnect after a token expiry silent rather than another prompt.
  const [existingGrant] = await sql`
    select grant_id, scope from oauth_grants where client_id = ${client_id} and revoked_at is null
  `;
  if (existingGrant) {
    // Silent re-approval may only hand back what the user actually
    // approved. A client asking for more than its grant covers has to go
    // through the consent page again rather than escalating unprompted.
    const requested = (scope ?? "").split(" ").filter(Boolean);
    const granted = (existingGrant.scope ?? "").split(" ").filter(Boolean);
    const escalates = requested.some((s: string) => !granted.includes(s));
    if (!escalates) {
      const code = await issueCode({
        clientId: client_id,
        redirectUri: redirect_uri,
        codeChallenge: code_challenge,
        scope: existingGrant.scope ?? "",
      });
      const target = new URL(redirect_uri);
      if (state) target.searchParams.set("state", state);
      target.searchParams.set("code", code);
      return c.redirect(target.toString());
    }
  }

  const requestId = randomUUID();
  await sql`
    insert into oauth_auth_requests (request_id, client_id, redirect_uri, code_challenge, state, scope, expires_at)
    values (
      ${requestId}, ${client_id}, ${redirect_uri}, ${code_challenge},
      ${state ?? null}, ${scope ?? ""},
      now() + ${`${AUTH_REQUEST_TTL_SECONDS} seconds`}::interval
    )
  `;

  return c.html(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authorize MCP access</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; text-align: center;">
  <h1>Authorize access</h1>
  <p>An application is requesting access to this MCP server.</p>
  <p style="color: #666; font-size: 0.9em;">Client: ${escapeHtml(client.client_name ?? client_id)}</p>
  <form method="POST" action="/authorize/decision" style="display: flex; gap: 1rem; justify-content: center; margin-top: 2rem;">
    <input type="hidden" name="request_id" value="${escapeHtml(requestId)}">
    <button type="submit" name="decision" value="approve" style="padding: 0.75rem 1.5rem; font-size: 1rem; cursor: pointer;">Approve</button>
    <button type="submit" name="decision" value="reject" style="padding: 0.75rem 1.5rem; font-size: 1rem; cursor: pointer;">Reject</button>
  </form>
</body>
</html>`);
});

oauth.post("/authorize/decision", async (c) => {
  const body = await c.req.parseBody();
  const requestId = String(body.request_id ?? "");
  const decision = String(body.decision ?? "");

  const [pending] = isUuid(requestId)
    ? await sql`
        delete from oauth_auth_requests
        where request_id = ${requestId} and expires_at > now()
        returning client_id, redirect_uri, code_challenge, state, scope
      `
    : [];
  if (!pending) return c.json({ error: "invalid_request", error_description: "unknown or expired request" }, 400);

  const redirectTarget = new URL(pending.redirect_uri);
  if (pending.state) redirectTarget.searchParams.set("state", pending.state);

  if (decision !== "approve") {
    redirectTarget.searchParams.set("error", "access_denied");
    return c.redirect(redirectTarget.toString());
  }

  // A fresh grant_id on every approval, so token generations stay
  // isolated: reviving the old id would let a stale pre-disconnect refresh
  // token trip replay detection and take down the session the user just
  // re-authorized. Old tokens cascade away with the replaced row.
  await sql`delete from oauth_grants where client_id = ${pending.client_id}`;
  const grantId = randomUUID();
  await sql`
    insert into oauth_grants (grant_id, client_id, scope)
    values (${grantId}, ${pending.client_id}, ${pending.scope})
  `;

  const code = await issueCode({
    clientId: pending.client_id,
    redirectUri: pending.redirect_uri,
    codeChallenge: pending.code_challenge,
    scope: pending.scope,
  });
  redirectTarget.searchParams.set("code", code);
  return c.redirect(redirectTarget.toString());
});

async function mintTokens(params: { clientId: string; grantId: string; scope: string }) {
  const accessToken = await new SignJWT({ scope: params.scope, clientId: params.clientId })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(params.clientId)
    .setIssuedAt()
    .setExpirationTime(`${ACCESS_TOKEN_TTL_SECONDS}s`)
    .sign(jwtSecret);

  const refreshToken = newSecret();
  await sql`
    insert into oauth_refresh_tokens (token_hash, grant_id, client_id, scope, expires_at)
    values (
      ${hashToken(refreshToken)}, ${params.grantId}, ${params.clientId}, ${params.scope},
      now() + ${`${REFRESH_TOKEN_TTL_DAYS} days`}::interval
    )
  `;

  return {
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: ACCESS_TOKEN_TTL_SECONDS,
    refresh_token: refreshToken,
    scope: params.scope,
  };
}

oauth.post("/token", async (c) => {
  const body = (await c.req.parseBody()) as Record<string, string>;
  const { grant_type, client_id } = body;

  if (grant_type === "authorization_code") {
    const { code, redirect_uri, code_verifier } = body;

    // Single-use: claim the code by stamping consumed_at, and only if it
    // wasn't already stamped. Doing it in one statement means two
    // simultaneous redemptions can't both win.
    const [pending] = code
      ? await sql`
          update oauth_auth_codes
          set consumed_at = now()
          where code_hash = ${hashToken(code)} and consumed_at is null and expires_at > now()
          returning client_id, redirect_uri, code_challenge, scope
        `
      : [];
    if (!pending) return c.json({ error: "invalid_grant", error_description: "code unknown, used, or expired" }, 400);

    if (pending.client_id !== client_id || pending.redirect_uri !== redirect_uri) {
      return c.json({ error: "invalid_grant" }, 400);
    }
    if (!code_verifier) return c.json({ error: "invalid_request", error_description: "missing code_verifier" }, 400);

    const computedChallenge = createHash("sha256").update(code_verifier).digest("base64url");
    if (!constantTimeEquals(computedChallenge, pending.code_challenge)) {
      return c.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
    }

    const [grant] = await sql`
      select grant_id from oauth_grants where client_id = ${pending.client_id} and revoked_at is null
    `;
    if (!grant) return c.json({ error: "invalid_grant", error_description: "grant revoked" }, 400);

    return c.json(await mintTokens({ clientId: pending.client_id, grantId: grant.grant_id, scope: pending.scope }));
  }

  if (grant_type === "refresh_token") {
    const presented = body.refresh_token;
    if (!presented) return c.json({ error: "invalid_request", error_description: "missing refresh_token" }, 400);
    const presentedHash = hashToken(presented);

    // Claim the token in a single conditional UPDATE, the same way the
    // authorization code is claimed above. A SELECT-then-UPDATE would let
    // two concurrent refreshes (a client retrying after a timeout, say)
    // both read the token as live and both mint a valid chain - which
    // would also mean the replay check below never fires.
    const [claimed] = await sql`
      update oauth_refresh_tokens set revoked_at = now()
      where token_hash = ${presentedHash}
        and revoked_at is null
        and rotated_to is null
        and expires_at > now()
      returning grant_id, client_id, scope
    `;

    if (!claimed) {
      // Nothing to claim: either we've never seen this token, or it's
      // expired, or it was already rotated/revoked. Only the last case is
      // a replay, and it means the token either leaked or the client is
      // buggy - so kill the whole grant, not just its tokens. Leaving the
      // grant alive would let the holder walk straight back in through
      // /authorize's silent re-approval path.
      const [known] = await sql`
        select grant_id, revoked_at, rotated_to,
               revoked_at < now() - ${`${REFRESH_REPLAY_GRACE_SECONDS} seconds`}::interval as outside_grace
        from oauth_refresh_tokens where token_hash = ${presentedHash}
      `;
      // Only an *old* rotated token counts as a replay. A client that fires
      // two refreshes at once, or retries after a timeout it never saw the
      // response to, presents the same token twice within seconds - that's
      // benign, and treating it as theft would log the client out for
      // being slightly racy. Inside the grace window we just decline.
      if (known && known.rotated_to && known.outside_grace) {
        await sql`update oauth_grants set revoked_at = now() where grant_id = ${known.grant_id}`;
        await sql`
          update oauth_refresh_tokens set revoked_at = now()
          where grant_id = ${known.grant_id} and revoked_at is null
        `;
        return c.json({ error: "invalid_grant", error_description: "refresh token replay detected" }, 400);
      }
      return c.json({ error: "invalid_grant" }, 400);
    }

    if (client_id && client_id !== claimed.client_id) return c.json({ error: "invalid_grant" }, 400);

    const [grant] = await sql`
      select grant_id from oauth_grants where grant_id = ${claimed.grant_id} and revoked_at is null
    `;
    if (!grant) return c.json({ error: "invalid_grant", error_description: "grant revoked" }, 400);

    const tokens = await mintTokens({
      clientId: claimed.client_id,
      grantId: claimed.grant_id,
      scope: claimed.scope,
    });
    await sql`
      update oauth_refresh_tokens
      set rotated_to = ${hashToken(tokens.refresh_token)}
      where token_hash = ${presentedHash}
    `;
    return c.json(tokens);
  }

  return c.json({ error: "unsupported_grant_type" }, 400);
});

// RFC 7009. Revoking a refresh token takes down the grant behind it, so the
// client is fully disconnected rather than left with a working access token
// until it happens to expire.
oauth.post("/revoke", async (c) => {
  const body = (await c.req.parseBody()) as Record<string, string>;
  const token = body.token;
  if (token) {
    // Match on the hash alone, not on `revoked_at is null` - a client that
    // has already rotated (or is sending a stale persisted copy) would
    // otherwise get a 200 saying "revoked" while the grant, and every live
    // token on it, kept working.
    const [row] = await sql`
      select grant_id from oauth_refresh_tokens where token_hash = ${hashToken(token)}
    `;
    if (row) {
      await sql`update oauth_grants set revoked_at = now() where grant_id = ${row.grant_id}`;
      await sql`
        update oauth_refresh_tokens set revoked_at = now()
        where grant_id = ${row.grant_id} and revoked_at is null
      `;
    }
  }
  // Always 200, even for an unknown token - per spec, so a caller can't
  // probe which tokens exist.
  return c.body(null, 200);
});

// Accepts either a self-issued OAuth token or the static MCP_AUTH_TOKEN
// (for Claude Desktop's header-based config, which has no OAuth flow).
const authenticateMcpRequest = mcpAuth(async (token) => {
  if (mcpAuthToken && token === mcpAuthToken) {
    return { token, scopes: [], clientId: "mcp-auth-token", extra: { userId: "mcp-auth-token" } };
  }
  let clientId: string | undefined;
  try {
    const { payload } = await jwtVerify(token, jwtSecret);
    clientId = typeof payload.clientId === "string" ? payload.clientId : undefined;
  } catch {
    return undefined; // bad signature or expired - genuinely unauthenticated
  }
  if (!isUuid(clientId)) return undefined;

  // The JWT is self-contained, but the grant behind it may have been
  // revoked since it was issued - so a revocation takes effect immediately
  // instead of waiting out the token's lifetime.
  //
  // This check is deliberately fail-open: the signature is already
  // verified, so a database outage means "we can't confirm a revocation",
  // not "this token is invalid". Returning undefined here would 401 every
  // connected client, and clients read a 401 on /mcp as "re-authorize" -
  // so a few seconds of Supabase unavailability would log everyone out,
  // which is the exact failure this whole change exists to prevent.
  try {
    const [grant] = await sql`
      select grant_id from oauth_grants where client_id = ${clientId} and revoked_at is null
    `;
    if (!grant) return undefined;
  } catch (err) {
    console.error("[oauth] grant check failed, allowing request on valid signature alone", err);
  }

  return { token, scopes: [], clientId, extra: { userId: clientId } };
});

oauth.post("/mcp", authenticateMcpRequest, streamableHttpHandler(createMcpServer));
