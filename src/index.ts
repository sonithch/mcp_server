import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { clerkMiddleware, getAuth } from "@clerk/hono";
import {
  mcpAuth,
  protectedResourceHandlerClerk,
  streamableHttpHandler,
} from "@clerk/mcp-tools/hono";
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

// OAuth server is Clerk itself - these describe how to reach it and what
// resource (/mcp) it protects. Clerk has no Dynamic Client Registration, so
// we fake it: /register always hands back the same pre-created public OAuth
// Application (no secret, PKCE-only) instead of minting a new Clerk client
// per caller. This lets any user add the server by URL alone - no manual
// client_id/secret entry - while every user still does their own Clerk
// sign-in/consent and gets their own personal access token.
app.get("/.well-known/oauth-protected-resource/mcp", protectedResourceHandlerClerk());

app.get("/.well-known/oauth-authorization-server", async (c) => {
  const publishableKey = process.env.CLERK_PUBLISHABLE_KEY;
  if (!publishableKey) return c.text("Server misconfigured: CLERK_PUBLISHABLE_KEY not set", 500);
  const metadata = await fetchClerkAuthorizationServerMetadata({ publishableKey });
  return c.json({
    ...metadata,
    ...(clerkPublicClientId ? { registration_endpoint: `${new URL(c.req.url).origin}/register` } : {}),
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
