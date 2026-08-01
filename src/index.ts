import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { clerkMiddleware, getAuth } from "@clerk/hono";
import {
  mcpAuth,
  protectedResourceHandlerClerk,
  authServerMetadataHandlerClerk,
  streamableHttpHandler,
} from "@clerk/mcp-tools/hono";
import { verifyClerkToken } from "@clerk/mcp-tools/server";
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

// OAuth server is Clerk itself - these two just describe how to reach it and
// what resource (/mcp) it protects. Create an "OAuth Application" in the
// Clerk Dashboard to get a client_id/secret for claude.ai (Clerk doesn't
// support Dynamic Client Registration).
app.get("/.well-known/oauth-protected-resource/mcp", protectedResourceHandlerClerk());
app.get("/.well-known/oauth-authorization-server", authServerMetadataHandlerClerk);

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
