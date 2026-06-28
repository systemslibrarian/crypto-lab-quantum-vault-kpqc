// Typed DOM query helpers.
//
// These replace bare non-null assertions (`querySelector(...)!`) at call sites.
// Instead of silently producing `null` (and a downstream "cannot read property
// of null" further away), they throw an explanatory error naming the missing
// selector — so a broken template fails loudly and obviously.

/** Query a required descendant element, throwing a clear error if it is absent. */
export function qs<T extends HTMLElement = HTMLElement>(
  root: ParentNode,
  selector: string,
): T {
  const el = root.querySelector<T>(selector);
  if (!el) throw new Error(`Required element not found: "${selector}"`);
  return el;
}

/** Look up a required element by id, throwing a clear error if it is absent. */
export function byId<T extends HTMLElement = HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Required element not found: "#${id}"`);
  return el as T;
}
