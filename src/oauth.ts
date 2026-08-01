import { Hono } from "hono";
import { getAuth } from "@clerk/hono";
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

let clerkMetadataCache: Awaited<ReturnType<typeof fetchClerkAuthorizationServerMetadata>> | undefined;
async function getClerkMetadata() {
  const publishableKey = process.env.CLERK_PUBLISHABLE_KEY;
  if (!publishableKey) throw new Error("CLERK_PUBLISHABLE_KEY not set");
  clerkMetadataCache ??= await fetchClerkAuthorizationServerMetadata({ publishableKey });
  return clerkMetadataCache;
}

export const oauth = new Hono();

oauth.get("/.well-known/oauth-protected-resource/mcp", (c) => {
  const origin = new URL(c.req.url).origin;
  return c.json({
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
  });
});

oauth.get("/.well-known/oauth-authorization-server", async (c) => {
  if (!clerkPublicClientId) return c.text("Server misconfigured: CLERK_PUBLIC_CLIENT_ID not set", 500);
  const origin = new URL(c.req.url).origin;
  const clerkMetadata = await getClerkMetadata();
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
    return c.json({ error: "invalid_request", error_description: "Dynamic registration is not configured" }, 400);
  }
  const body = await c.req
    .json<{ redirect_uris?: string[] }>()
    .catch((): { redirect_uris?: string[] } => ({}));
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
  if (!clerkPublicClientId) return c.text("Server misconfigured: CLERK_PUBLIC_CLIENT_ID not set", 500);
  const clerkMetadata = await getClerkMetadata();
  const target = new URL(clerkMetadata.authorization_endpoint);
  for (const [key, value] of new URL(c.req.url).searchParams) {
    target.searchParams.set(key, value);
  }
  target.searchParams.set("client_id", clerkPublicClientId);
  return c.redirect(target.toString());
});

oauth.post("/token", async (c) => {
  if (!clerkPublicClientId) return c.text("Server misconfigured: CLERK_PUBLIC_CLIENT_ID not set", 500);
  const clerkMetadata = await getClerkMetadata();
  const incoming = await c.req.formData();
  const outgoing = new URLSearchParams();
  for (const [key, value] of incoming) {
    if (key === "client_id" || key === "client_secret") continue;
    outgoing.set(key, String(value));
  }
  outgoing.set("client_id", clerkPublicClientId);

  const upstream = await fetch(clerkMetadata.token_endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: outgoing,
  });
  return new Response(upstream.body, { status: upstream.status, headers: upstream.headers });
});

// Accepts either a Clerk-issued OAuth token or the static MCP_AUTH_TOKEN
// (for Claude Desktop's header-based config, which has no OAuth flow).
const authenticateMcpRequest = mcpAuth(async (token, c) => {
  if (mcpAuthToken && token === mcpAuthToken) {
    return { token, scopes: [], clientId: "mcp-auth-token", extra: { userId: "mcp-auth-token" } };
  }
  const authData = getAuth(c, { acceptsToken: "oauth_token" });
  if (!authData.isAuthenticated) return undefined;
  return verifyClerkToken(authData, token);
});

oauth.post("/mcp", authenticateMcpRequest, streamableHttpHandler(createMcpServer));
