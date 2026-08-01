import { serve } from "@hono/node-server";
import { Hono } from "hono";

type Item = {
  id: number;
  name: string;
  description: string;
};

const app = new Hono();

let items: Item[] = [];
let nextId = 1;

// Create
app.post("/items", async (c) => {
  const body = await c.req.json<Partial<Item>>();
  if (!body.name) {
    return c.json({ error: "name is required" }, 400);
  }

  const item: Item = {
    id: nextId++,
    name: body.name,
    description: body.description ?? "",
  };
  items.push(item);
  return c.json(item, 201);
});

// Search (must be defined before /items/:id)
app.get("/items/search", (c) => {
  const q = c.req.query("q")?.toLowerCase() ?? "";
  const results = items.filter(
    (item) =>
      item.name.toLowerCase().includes(q) ||
      item.description.toLowerCase().includes(q)
  );
  return c.json(results);
});

// Read all
app.get("/items", (c) => {
  return c.json(items);
});

// Read one
app.get("/items/:id", (c) => {
  const id = Number(c.req.param("id"));
  const item = items.find((i) => i.id === id);
  if (!item) return c.json({ error: "not found" }, 404);
  return c.json(item);
});

// Update
app.put("/items/:id", async (c) => {
  const id = Number(c.req.param("id"));
  const item = items.find((i) => i.id === id);
  if (!item) return c.json({ error: "not found" }, 404);

  const body = await c.req.json<Partial<Item>>();
  if (body.name !== undefined) item.name = body.name;
  if (body.description !== undefined) item.description = body.description;

  return c.json(item);
});

// Delete
app.delete("/items/:id", (c) => {
  const id = Number(c.req.param("id"));
  const index = items.findIndex((i) => i.id === id);
  if (index === -1) return c.json({ error: "not found" }, 404);

  const [deleted] = items.splice(index, 1);
  return c.json(deleted);
});

const port = 3001;
console.log(`Server running at http://localhost:${port}`);

serve({
  fetch: app.fetch,
  port,
});
