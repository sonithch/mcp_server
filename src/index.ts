import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { clerkMiddleware, getAuth } from "@clerk/hono";
import { mcpAuth, streamableHttpHandler } from "@clerk/mcp-tools/hono";
import { fetchClerkAuthorizationServerMetadata, verifyClerkToken } from "@clerk/mcp-tools/server";
import { createMcpServer } from "./mcp-server.js";
import {
  listItems,
  getItem,
  createItem,
  createItems,
  updateItem,
  deleteItem,
  searchItems,
} from "./items-store.js";

const app = new Hono();

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "mcp-session-id", "Last-Event-ID", "mcp-protocol-version"],
    exposeHeaders: ["mcp-session-id", "mcp-protocol-version"],
  })
);
app.use("*", clerkMiddleware());

app.get("/health", (c) => c.json({ status: "ok" }));

const port = Number(process.env.PORT) || 3001;
const mcpAuthToken = process.env.MCP_AUTH_TOKEN;
const clerkPublicClientId = process.env.CLERK_PUBLIC_CLIENT_ID;

// We declare OURSELVES as the OAuth issuer (not Clerk) so that spec-compliant
// clients discover authorization-server metadata - including /register - from
// our own domain. Per RFC 8414/9728, a client fetches AS metadata from the
// issuer's own host, so pointing authorization_servers at Clerk directly (as
// @clerk/mcp-tools' Clerk-flavored helpers do) means our injected
// registration_endpoint would never be seen: the client would fetch Clerk's
// real, unmodified metadata (no DCR support) straight from Clerk's domain.
// Instead, /authorize and /token below thinly proxy to Clerk's real endpoints.
let clerkMetadataCache: Awaited<ReturnType<typeof fetchClerkAuthorizationServerMetadata>> | undefined;
async function getClerkMetadata() {
  const publishableKey = process.env.CLERK_PUBLISHABLE_KEY;
  if (!publishableKey) throw new Error("CLERK_PUBLISHABLE_KEY not set");
  clerkMetadataCache ??= await fetchClerkAuthorizationServerMetadata({ publishableKey });
  return clerkMetadataCache;
}

app.get("/.well-known/oauth-protected-resource/mcp", (c) => {
  const origin = new URL(c.req.url).origin;
  return c.json({
    resource: `${origin}/mcp`,
    authorization_servers: [origin],
  });
});

app.get("/.well-known/oauth-authorization-server", async (c) => {
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

app.post("/register", async (c) => {
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
app.get("/authorize", async (c) => {
  if (!clerkPublicClientId) return c.text("Server misconfigured: CLERK_PUBLIC_CLIENT_ID not set", 500);
  const clerkMetadata = await getClerkMetadata();
  const target = new URL(clerkMetadata.authorization_endpoint);
  for (const [key, value] of new URL(c.req.url).searchParams) {
    target.searchParams.set(key, value);
  }
  target.searchParams.set("client_id", clerkPublicClientId);
  return c.redirect(target.toString());
});

app.post("/token", async (c) => {
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

app.post("/mcp", authenticateMcpRequest, streamableHttpHandler(createMcpServer));

// Create
app.post("/items", async (c) => {
  const body = await c.req.json<{ name?: string; description?: string }>();
  if (!body.name) {
    return c.json({ error: "name is required" }, 400);
  }
  return c.json(createItem(body.name, body.description ?? "", "api"), 201);
});

// Batch create
app.post("/items/batch", async (c) => {
  const body = await c.req.json<{ items?: { name?: string; description?: string }[] }>();
  if (!Array.isArray(body.items) || body.items.length === 0) {
    return c.json({ error: "items must be a non-empty array" }, 400);
  }
  const invalidIndex = body.items.findIndex((item) => !item.name);
  if (invalidIndex !== -1) {
    return c.json({ error: `items[${invalidIndex}].name is required` }, 400);
  }
  const created = createItems(body.items as { name: string; description?: string }[], "api");
  return c.json(created, 201);
});

// Search (must be defined before /items/:id)
app.get("/items/search", (c) => {
  const q = c.req.query("q")?.toLowerCase() ?? "";
  return c.json(searchItems(q));
});

// Read all
app.get("/items", (c) => c.json(listItems()));

// Read one
app.get("/items/:id", (c) => {
  const item = getItem(Number(c.req.param("id")));
  if (!item) return c.json({ error: "not found" }, 404);
  return c.json(item);
});

// Update
app.put("/items/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const body = await c.req.json<{ name?: string; description?: string }>();
  const item = updateItem(id, body, "api");
  if (!item) return c.json({ error: "not found" }, 404);
  return c.json(item);
});

// Delete
app.delete("/items/:id", (c) => {
  const item = deleteItem(Number(c.req.param("id")));
  if (!item) return c.json({ error: "not found" }, 404);
  return c.json(item);
});

console.log(`Server running at http://localhost:${port}`);
console.log(`MCP endpoint: http://localhost:${port}/mcp`);

serve({
  fetch: app.fetch,
  port,
});
