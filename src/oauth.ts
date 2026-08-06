import { Hono } from "hono";
import { clerkMiddleware, getAuth } from "@clerk/hono";
import { mcpAuth, streamableHttpHandler } from "@clerk/mcp-tools/hono";
import { fetchClerkAuthorizationServerMetadata, verifyClerkToken } from "@clerk/mcp-tools/server";
import { createMcpServer } from "./mcp-server.js";

// We declare OURSELVES as the OAuth issuer (not Clerk) so that spec-compliant
// clients discover authorization-server metadata - including /register - from
// our own domain. Per RFC 8414/9728, a client fetches AS metadata from the
// issuer's own host, so pointing authorization_servers at Clerk directly (as
// @clerk/mcp-tools' Clerk-flavored helpers do) means our injected
// registration_endpoint would never be seen: the client would fetch Clerk's
// real, unmodified metadata (no DCR support) straight from Clerk's domain.
// Instead, /authorize and /token below thinly proxy to Clerk's real endpoints.

const mcpAuthToken = process.env.MCP_AUTH_TOKEN;
const clerkPublicClientId = process.env.CLERK_PUBLIC_CLIENT_ID;

// Render (and most PaaS providers) terminate TLS at the edge and forward
// plain HTTP internally, so c.req.url's own scheme is always "http" even
// though the real, public-facing request was https. Self-advertising
// "http://" endpoints in our OAuth metadata makes them unusable: clients
// correctly refuse to exchange an authorization code for tokens over an
// unencrypted URL, so /token was silently never being called. Trust
// X-Forwarded-Proto/Host (set by the proxy) over the request's own URL.
function getPublicOrigin(c: { req: { url: string; header: (name: string) => string | undefined } }): string {
  const url = new URL(c.req.url);
  const proto = c.req.header("x-forwarded-proto")?.split(",")[0]?.trim() ?? url.protocol.replace(":", "");
  const host = c.req.header("x-forwarded-host")?.split(",")[0]?.trim() ?? url.host;
  return `${proto}://${host}`;
}

let clerkMetadataCache: Awaited<ReturnType<typeof fetchClerkAuthorizationServerMetadata>> | undefined;
async function getClerkMetadata() {
  const publishableKey = process.env.CLERK_PUBLISHABLE_KEY;
  if (!publishableKey) throw new Error("CLERK_PUBLISHABLE_KEY not set");
  clerkMetadataCache ??= await fetchClerkAuthorizationServerMetadata({ publishableKey });
  return clerkMetadataCache;
}

export const oauth = new Hono();

oauth.get("/.well-known/oauth-protected-resource/mcp", (c) => {
  const origin = getPublicOrigin(c);
  console.log("[oauth] GET /.well-known/oauth-protected-resource/mcp", { origin });
  return c.json({
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
  });
});

oauth.get("/.well-known/oauth-authorization-server", async (c) => {
  const origin = getPublicOrigin(c);
  console.log("[oauth] GET /.well-known/oauth-authorization-server", { origin });
  if (!clerkPublicClientId) {
    console.error("[oauth] CLERK_PUBLIC_CLIENT_ID not set");
    return c.text("Server misconfigured: CLERK_PUBLIC_CLIENT_ID not set", 500);
  }
  const clerkMetadata = await getClerkMetadata().catch((err) => {
    console.error("[oauth] fetchClerkAuthorizationServerMetadata failed", err);
    throw err;
  });
  return c.json({
    ...clerkMetadata,
    issuer: origin,
    authorization_endpoint: `${origin}/authorize`,
    token_endpoint: `${origin}/token`,
    registration_endpoint: `${origin}/register`,
    token_endpoint_auth_methods_supported: ["none"],
  });
});

// Clerk has no Dynamic Client Registration, so we fake it: /register always
// hands back the same pre-created public OAuth Application (no secret,
// PKCE-only) instead of minting a new Clerk client per caller. This lets any
// user add the server by URL alone - no manual client_id/secret entry -
// while every user still does their own Clerk sign-in/consent and gets their
// own personal access token.
oauth.post("/register", async (c) => {
  if (!clerkPublicClientId) {
    console.error("[oauth] POST /register: CLERK_PUBLIC_CLIENT_ID not set");
    return c.json({ error: "invalid_request", error_description: "Dynamic registration is not configured" }, 400);
  }
  const body = await c.req
    .json<{ redirect_uris?: string[] }>()
    .catch((): { redirect_uris?: string[] } => ({}));
  console.log("[oauth] POST /register", { redirect_uris: body.redirect_uris });
  return c.json(
    {
      client_id: clerkPublicClientId,
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code", "refresh_token"],
      response_types: ["code"],
      redirect_uris: body.redirect_uris ?? [],
    },
    201
  );
});

// Thin proxies to Clerk's real authorize/token endpoints, always substituting
// in the one shared public client_id regardless of what the caller sends.
oauth.get("/authorize", async (c) => {
  if (!clerkPublicClientId) {
    console.error("[oauth] GET /authorize: CLERK_PUBLIC_CLIENT_ID not set");
    return c.text("Server misconfigured: CLERK_PUBLIC_CLIENT_ID not set", 500);
  }
  const clerkMetadata = await getClerkMetadata();
  const target = new URL(clerkMetadata.authorization_endpoint);
  for (const [key, value] of new URL(c.req.url).searchParams) {
    target.searchParams.set(key, value);
  }
  target.searchParams.set("client_id", clerkPublicClientId);
  console.log("[oauth] GET /authorize -> redirecting to Clerk", {
    incomingParams: Object.fromEntries(new URL(c.req.url).searchParams),
    target: target.toString(),
  });
  return c.redirect(target.toString());
});

oauth.post("/token", async (c) => {
  if (!clerkPublicClientId) {
    console.error("[oauth] POST /token: CLERK_PUBLIC_CLIENT_ID not set");
    return c.text("Server misconfigured: CLERK_PUBLIC_CLIENT_ID not set", 500);
  }
  const clerkMetadata = await getClerkMetadata();
  const incoming = await c.req.formData();
  const outgoing = new URLSearchParams();
  for (const [key, value] of incoming) {
    if (key === "client_id" || key === "client_secret") continue;
    outgoing.set(key, String(value));
  }
  outgoing.set("client_id", clerkPublicClientId);

  console.log("[oauth] POST /token -> forwarding to Clerk", {
    grant_type: outgoing.get("grant_type"),
    redirect_uri: outgoing.get("redirect_uri"),
    hasCode: outgoing.has("code"),
    hasCodeVerifier: outgoing.has("code_verifier"),
    hasRefreshToken: outgoing.has("refresh_token"),
    target: clerkMetadata.token_endpoint,
  });

  const upstream = await fetch(clerkMetadata.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: outgoing,
  });
  if (!upstream.ok) {
    const body = await upstream.clone().text();
    console.error("[oauth] Clerk token exchange failed", { status: upstream.status, body });
  } else {
    console.log("[oauth] Clerk token exchange succeeded", { status: upstream.status });
  }
  return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });
});

// Accepts either a Clerk-issued OAuth token or the static MCP_AUTH_TOKEN
// (for Claude Desktop's header-based config, which has no OAuth flow).
const authenticateMcpRequest = mcpAuth(async (token, c) => {
  console.log("[mcp-auth] POST /mcp auth check", { hasToken: Boolean(token), tokenPrefix: token?.slice(0, 12) });
  if (mcpAuthToken && token === mcpAuthToken) {
    console.log("[mcp-auth] matched static MCP_AUTH_TOKEN");
    return { token, scopes: [], clientId: "mcp-auth-token", extra: { userId: "mcp-auth-token" } };
  }
  const authData = getAuth(c, { acceptsToken: "oauth_token" });
  if (!authData.isAuthenticated) {
    console.error("[mcp-auth] getAuth reported not authenticated", {
      hasToken: Boolean(token),
      tokenPrefix: token?.slice(0, 12),
      reason: (authData as { reason?: unknown }).reason,
    });
    return undefined;
  }
  try {
    const result = await verifyClerkToken(authData, token);
    console.log("[mcp-auth] verifyClerkToken succeeded", { userId: (result as { extra?: { userId?: unknown } })?.extra?.userId });
    return result;
  } catch (err) {
    console.error("[mcp-auth] verifyClerkToken threw", err);
    throw err;
  }
});

// clerkMiddleware() is scoped to just this route (not applied globally in
// index.ts) because it proactively tries to establish/verify Clerk session
// state on every request it wraps - including, when mounted globally, on
// /authorize itself. On a Clerk *development* instance (no stable custom
// domain) that triggers Clerk's cookie-sync "handshake" redirect, and
// re-entering /authorize mid-flow was re-triggering it, causing a redirect
// loop that never reached Clerk's real login screen. /authorize, /register,
// and /token are pure proxies that never call getAuth() and don't need this
// middleware at all.
oauth.post("/mcp", clerkMiddleware(), authenticateMcpRequest, streamableHttpHandler(createMcpServer));
