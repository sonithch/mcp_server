import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { oauth } from "./oauth.js";
import { migrate, sweepExpired } from "./db.js";
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

app.use("*", logger());
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

app.route("/", oauth);

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

const port = Number(process.env.PORT) || 3001;

// The schema is created before the server accepts traffic - a boot that
// can't reach Postgres should fail loudly rather than serve an OAuth
// server that silently can't remember anyone.
await migrate();

// Abandoned auth flows and long-dead tokens would otherwise accumulate.
sweepExpired().catch((err) => console.error("[db] sweep failed", err));
setInterval(() => {
  sweepExpired().catch((err) => console.error("[db] sweep failed", err));
}, 60 * 60 * 1000).unref();

console.log(`Server running at http://localhost:${port}`);
console.log(`MCP endpoint: http://localhost:${port}/mcp`);

serve({
  fetch: app.fetch,
  port,
});
