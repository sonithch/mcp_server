import { Hono } from "hono";
import { mcpAuth, streamableHttpHandler } from "@clerk/mcp-tools/hono";
import { auth } from "./auth.js";
import { createMcpServer } from "./mcp-server.js";

// This server is its own OAuth 2.0 / OIDC authorization server, backed by
// better-auth (src/auth.ts) rather than an external identity provider like
// Clerk. better-auth owns Dynamic Client Registration, PKCE-enforced
// /authorize + /token, the users table, and Google sign-in. This file is
// thin: it exposes the paths an MCP client expects at the root of the
// domain, forwards to better-auth's real handler mounted at /api/auth/*,
// and verifies bearer tokens on /mcp.

const mcpAuthToken = process.env.MCP_AUTH_TOKEN;

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
    authorization_endpoint: `${origin}/api/auth/mcp/authorize`,
    token_endpoint: `${origin}/api/auth/mcp/token`,
    registration_endpoint: `${origin}/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["none"],
    subject_types_supported: ["public"],
  });
});

// better-auth's own DCR endpoint requires client_name (a NOT NULL column)
// and defaults token_endpoint_auth_method to "client_secret_basic" if
// omitted, which would register a confidential client. Real MCP clients
// (e.g. Claude.ai) send neither field - they expect a PKCE-only public
// client with no name. This wrapper fills in both defaults before
// forwarding to the real endpoint.
oauth.post("/register", async (c) => {
  const body = await c.req.json<Record<string, unknown>>().catch((): Record<string, unknown> => ({}));
  body.client_name ??= "MCP Client";
  body.token_endpoint_auth_method ??= "none";

  const origin = getPublicOrigin(c);
  const upstream = await auth.handler(
    new Request(`${origin}/api/auth/mcp/register`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    })
  );
  return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });
});

// Rendered when better-auth's /authorize needs a session and redirects here
// (its `loginPage` option). Preserves the original OAuth query params so
// they survive the round trip through Google.
oauth.get("/authorize/login", (c) => {
  const query = new URL(c.req.url).search;
  return c.html(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Sign in</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; text-align: center;">
  <h1>Sign in required</h1>
  <p>Sign in to authorize this application's access.</p>
  <button id="google" style="padding: 0.75rem 1.5rem; font-size: 1rem; cursor: pointer;">Sign in with Google</button>
  <script>
    document.getElementById("google").onclick = async () => {
      const res = await fetch("/api/auth/sign-in/social", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ provider: "google", callbackURL: "/authorize${query}" }),
      });
      const data = await res.json();
      if (data.url) window.location.href = data.url;
    };
  </script>
</body>
</html>`);
});

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[ch]!);
}

// Rendered when better-auth's /authorize needs explicit consent (the
// client requested prompt=consent) and redirects here (its `consentPage`
// option), passing consent_code/client_id/scope as query params. Approve
// and Reject both POST to better-auth's real /oauth2/consent endpoint,
// which returns { redirectURI } as JSON rather than an HTTP redirect - the
// tiny bit of JS just follows it.
oauth.get("/authorize/consent", (c) => {
  const { consent_code, client_id, scope } = c.req.query();
  if (!consent_code || !client_id) return c.text("Missing consent_code or client_id", 400);

  return c.html(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Authorize MCP access</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 480px; margin: 4rem auto; text-align: center;">
  <h1>Authorize access</h1>
  <p>An application is requesting access to this MCP server.</p>
  <p style="color: #666; font-size: 0.85em;">Client: ${escapeHtml(client_id)}<br>Scopes: ${escapeHtml(scope ?? "")}</p>
  <div style="display: flex; gap: 1rem; justify-content: center; margin-top: 2rem;">
    <button id="approve" style="padding: 0.75rem 1.5rem; font-size: 1rem; cursor: pointer;">Approve</button>
    <button id="reject" style="padding: 0.75rem 1.5rem; font-size: 1rem; cursor: pointer;">Reject</button>
  </div>
  <script>
    async function decide(accept) {
      const res = await fetch("/api/auth/oauth2/consent", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ accept, consent_code: ${JSON.stringify(consent_code)} }),
      });
      const data = await res.json();
      if (data.redirectURI) window.location.href = data.redirectURI;
    }
    document.getElementById("approve").onclick = () => decide(true);
    document.getElementById("reject").onclick = () => decide(false);
  </script>
</body>
</html>`);
});

oauth.get("/authorize", async (c) => {
  const origin = getPublicOrigin(c);
  const target = new URL(`${origin}/api/auth/mcp/authorize`);
  target.search = new URL(c.req.url).search;
  const upstream = await auth.handler(new Request(target, { headers: c.req.raw.headers }));
  return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });
});

// Everything else better-auth owns (sign-in, callbacks, session, consent,
// token exchange) is mounted directly.
oauth.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

// Accepts either a better-auth-issued OAuth token or the static
// MCP_AUTH_TOKEN (for Claude Desktop's header-based config, which has no
// OAuth flow).
const authenticateMcpRequest = mcpAuth(async (token, c) => {
  if (mcpAuthToken && token === mcpAuthToken) {
    return { token, scopes: [], clientId: "mcp-auth-token", extra: { userId: "mcp-auth-token" } };
  }
  const session = await auth.api.getMcpSession({ headers: c.req.raw.headers });
  if (!session) return undefined;
  return {
    token: session.accessToken,
    scopes: session.scopes ? session.scopes.split(" ") : [],
    clientId: session.clientId,
    extra: { userId: session.userId ?? "unknown" },
  };
});

oauth.post("/mcp", authenticateMcpRequest, streamableHttpHandler(createMcpServer));
