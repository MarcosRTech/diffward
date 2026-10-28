import { useEffect, useState } from "react";

async function fetchItems(): Promise<string[]> {
  const res = await fetch("/api/items");
  return res.json();
}

export function Items() {
  const [items, setItems] = useState<string[]>([]);
  useEffect(() => {
    async function load() {
      setItems(await fetchItems());
    }
    // In a component, fire-and-forget loading is the usual pattern.
    // ok: js/floating-promise
    load();
  }, []);
  // ok: js/http-no-timeout
  void fetch("/api/ping");
  return items.join(",");
}
