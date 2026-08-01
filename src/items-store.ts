export type Item = {
  id: number;
  name: string;
  description: string;
};

let items: Item[] = [];
let nextId = 1;

export function listItems(): Item[] {
  return items;
}

export function getItem(id: number): Item | undefined {
  return items.find((i) => i.id === id);
}

export function createItem(name: string, description = ""): Item {
  const item: Item = { id: nextId++, name, description };
  items.push(item);
  return item;
}

export function updateItem(
  id: number,
  changes: { name?: string; description?: string }
): Item | undefined {
  const item = getItem(id);
  if (!item) return undefined;
  if (changes.name !== undefined) item.name = changes.name;
  if (changes.description !== undefined) item.description = changes.description;
  return item;
}

export function deleteItem(id: number): Item | undefined {
  const index = items.findIndex((i) => i.id === id);
  if (index === -1) return undefined;
  const [deleted] = items.splice(index, 1);
  return deleted;
}

export function searchItems(q: string): Item[] {
  const query = q.toLowerCase();
  return items.filter(
    (item) =>
      item.name.toLowerCase().includes(query) ||
      item.description.toLowerCase().includes(query)
  );
}
