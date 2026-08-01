import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { WebStandardStreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js";
import { createMcpServer } from "./mcp-server.js";
import { createOAuthRoutes, getAccessTokenUserId } from "./oauth.js";
import {
  listItems,
  getItem,
  createItem,
  createItems,
  updateItem,
  deleteItem,
  searchItems,
} from "./items-store.js";

const app = new Hono<{ Variables: { actor: string } }>();

app.use(
  "*",
  cors({
    origin: "*",
    allowMethods: ["GET", "POST", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "mcp-session-id", "Last-Event-ID", "mcp-protocol-version"],
    exposeHeaders: ["mcp-session-id", "mcp-protocol-version"],
  })
);

app.get("/health", (c) => c.json({ status: "ok" }));

const port = Number(process.env.PORT) || 3001;
const baseUrl = process.env.PUBLIC_URL || process.env.RENDER_EXTERNAL_URL || `http://localhost:${port}`;
const mcpAuthToken = process.env.MCP_AUTH_TOKEN;

app.route("/", createOAuthRoutes(baseUrl));

app.use("/mcp", async (c, next) => {
  const authHeader = c.req.header("Authorization");
  const bearer = authHeader?.startsWith("Bearer ") ? authHeader.slice(7) : undefined;
  const oauthUserId = bearer !== undefined ? getAccessTokenUserId(bearer) : undefined;
  const authorized = bearer !== undefined && (bearer === mcpAuthToken || oauthUserId !== undefined);
  if (!authorized) {
    c.header(
      "WWW-Authenticate",
      `Bearer resource_metadata="${baseUrl}/.well-known/oauth-protected-resource"`
    );
    return c.json({ error: "unauthorized" }, 401);
  }
  c.set("actor", oauthUserId ?? "mcp-auth-token");
  await next();
});

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

// MCP endpoint - stateless: fresh transport + server per request
app.all("/mcp", async (c) => {
  const transport = new WebStandardStreamableHTTPServerTransport();
  const server = createMcpServer(c.get("actor"));
  await server.connect(transport);
  return transport.handleRequest(c.req.raw);
});

console.log(`Server running at http://localhost:${port}`);
console.log(`MCP endpoint: http://localhost:${port}/mcp`);

serve({
  fetch: app.fetch,
  port,
});
