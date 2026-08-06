import { Hono } from "hono";
import { randomUUID, randomBytes, createHash } from "node:crypto";
import { SignJWT, jwtVerify } from "jose";
import { mcpAuth, streamableHttpHandler } from "@clerk/mcp-tools/hono";
import { createMcpServer } from "./mcp-server.js";

// This server is its own, self-contained OAuth 2.0 authorization server -
// no external identity provider. There's no real user login: /authorize
// renders a plain Approve/Reject page, and clicking Approve is the entire
// "authentication" step. This trades real identity for simplicity; anyone
// who reaches the server URL can grant themselves access. Fine for a
// personal/low-stakes MCP server, not something to reuse for anything that
// needs real access control.

const mcpAuthToken = process.env.MCP_AUTH_TOKEN;

// Signs/verifies our own access tokens. Falls back to a random secret
// generated at boot if none is set - tokens then just stop working across
// restarts (everyone re-approves), which is an acceptable tradeoff for how
// this auth model works, but set OAUTH_JWT_SECRET in production to avoid
// invalidating tokens on every deploy.
const jwtSecret = new TextEncoder().encode(process.env.OAUTH_JWT_SECRET ?? randomBytes(32).toString("hex"));
if (!process.env.OAUTH_JWT_SECRET) {
  console.warn("[oauth] OAUTH_JWT_SECRET not set - using an ephemeral secret; tokens won't survive a restart");
}

interface RegisteredClient {
  redirectUris: string[];
}
const registeredClients = new Map<string, RegisteredClient>();

interface PendingAuthRequest {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state?: string;
  scope: string;
}
const pendingAuthRequests = new Map<string, PendingAuthRequest>();

interface PendingCode {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  scope: string;
  expiresAt: number;
}
const pendingCodes = new Map<string, PendingCode>();

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
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    subject_types_supported: ["public"],
  });
});

// Real Dynamic Client Registration (RFC 7591): unlike the earlier
// Clerk-backed version, we own the whole authorization server, so we can
// actually mint a distinct client_id per caller instead of faking it.
oauth.post("/register", async (c) => {
  const body = await c.req
    .json<{ redirect_uris?: string[] }>()
    .catch((): { redirect_uris?: string[] } => ({}));
  const redirectUris = body.redirect_uris ?? [];
  if (redirectUris.length === 0) {
    return c.json({ error: "invalid_client_metadata", error_description: "redirect_uris is required" }, 400);
  }

  const clientId = randomUUID();
  registeredClients.set(clientId, { redirectUris });

  return c.json(
    {
      client_id: clientId,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: redirectUris,
    },
    201
  );
});

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}

// No real login - this page IS the entire authentication step. Approve
// mints an authorization code for whoever clicked it; Reject sends the
// client an access_denied error. See the module-level comment for why.
oauth.get("/authorize", (c) => {
  const { response_type, client_id, redirect_uri, code_challenge, code_challenge_method, state, scope } =
    c.req.query();

  const client = client_id ? registeredClients.get(client_id) : undefined;
  if (!client) return c.json({ error: "invalid_client" }, 400);
  if (!redirect_uri || !client.redirectUris.includes(redirect_uri)) {
    return c.json({ error: "invalid_request", error_description: "redirect_uri does not match registration" }, 400);
  }
  if (response_type !== "code") return c.json({ error: "unsupported_response_type" }, 400);
  if (!code_challenge || code_challenge_method !== "S256") {
    return c.json({ error: "invalid_request", error_description: "PKCE (S256) is required" }, 400);
  }

  const requestId = randomUUID();
  pendingAuthRequests.set(requestId, { clientId: client_id, redirectUri: redirect_uri, codeChallenge: code_challenge, state, scope: scope ?? "" });

  return c.html(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authorize MCP access</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; text-align: center;">
  <h1>Authorize access</h1>
  <p>An application is requesting access to this MCP server.</p>
  <p style="color: #666; font-size: 0.9em;">Client: ${escapeHtml(client_id)}</p>
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

  const pending = pendingAuthRequests.get(requestId);
  if (!pending) return c.json({ error: "invalid_request", error_description: "unknown or expired request" }, 400);
  pendingAuthRequests.delete(requestId); // single-use

  const redirectTarget = new URL(pending.redirectUri);
  if (pending.state) redirectTarget.searchParams.set("state", pending.state);

  if (decision !== "approve") {
    redirectTarget.searchParams.set("error", "access_denied");
    return c.redirect(redirectTarget.toString());
  }

  const code = randomUUID();
  pendingCodes.set(code, {
    clientId: pending.clientId,
    redirectUri: pending.redirectUri,
    codeChallenge: pending.codeChallenge,
    scope: pending.scope,
    expiresAt: Date.now() + 60_000,
  });
  redirectTarget.searchParams.set("code", code);
  return c.redirect(redirectTarget.toString());
});

oauth.post("/token", async (c) => {
  const body = await c.req.parseBody();
  const { grant_type, code, redirect_uri, client_id, code_verifier } = body as Record<string, string>;

  if (grant_type !== "authorization_code") return c.json({ error: "unsupported_grant_type" }, 400);

  const pending = code ? pendingCodes.get(code) : undefined;
  if (!pending || pending.expiresAt < Date.now()) {
    return c.json({ error: "invalid_grant", error_description: "code unknown or expired" }, 400);
  }
  pendingCodes.delete(code); // single-use

  if (pending.clientId !== client_id || pending.redirectUri !== redirect_uri) {
    return c.json({ error: "invalid_grant" }, 400);
  }
  if (!code_verifier) return c.json({ error: "invalid_request", error_description: "missing code_verifier" }, 400);

  const computedChallenge = createHash("sha256").update(code_verifier).digest("base64url");
  if (computedChallenge !== pending.codeChallenge) {
    return c.json({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
  }

  const accessToken = await new SignJWT({ scope: pending.scope, clientId: pending.clientId })
    .setProtectedHeader({ alg: "HS256" })
    .setSubject(pending.clientId)
    .setIssuedAt()
    .setExpirationTime("30d")
    .sign(jwtSecret);

  return c.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 60 * 60 * 24 * 30,
    scope: pending.scope,
  });
});

// Accepts either a self-issued OAuth token or the static MCP_AUTH_TOKEN
// (for Claude Desktop's header-based config, which has no OAuth flow).
const authenticateMcpRequest = mcpAuth(async (token) => {
  if (mcpAuthToken && token === mcpAuthToken) {
    return { token, scopes: [], clientId: "mcp-auth-token", extra: { userId: "mcp-auth-token" } };
  }
  try {
    const { payload } = await jwtVerify(token, jwtSecret);
    const clientId = typeof payload.clientId === "string" ? payload.clientId : "unknown-client";
    return { token, scopes: [], clientId, extra: { userId: clientId } };
  } catch {
    return undefined;
  }
});

oauth.post("/mcp", authenticateMcpRequest, streamableHttpHandler(createMcpServer));
