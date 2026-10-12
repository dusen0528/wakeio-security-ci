import { types } from "node:util";
/** Bounded JSON data only; never invoke accessors, toJSON or custom prototypes. */
export const JSON_MAX_INPUT_BYTES = 1024 * 1024;
export const JSON_MAX_INPUT_NODES = 20_000;
export const JSON_MAX_DEPTH = 40;
function fail(): never { throw new TypeError("invalid_bounded_json"); }

/** Snapshot data properties without invoking getters, toJSON, or caller mutation later. */
export function snapshotJsonData(input: unknown, invalid: () => never = fail, limit: () => never = fail): unknown {
  let nodes = 0, bytes = 0;
  const active = new Set<object>();
  const count = (value: string) => { bytes += Buffer.byteLength(value, "utf8"); if (bytes > JSON_MAX_INPUT_BYTES) limit(); };
  const string = (value: string) => { if (value.length > JSON_MAX_INPUT_BYTES) limit(); count(JSON.stringify(value)); };
  const copy = (value: unknown, depth: number): unknown => {
    if (++nodes > JSON_MAX_INPUT_NODES || depth > JSON_MAX_DEPTH) limit();
    if (value === null || typeof value === "boolean") { count(String(value)); return value; }
    if (typeof value === "string") { string(value); return value; }
    if (typeof value === "number") { if (!Number.isFinite(value)) invalid(); count(String(value)); return value; }
    if (typeof value !== "object" || types.isProxy(value) || active.has(value)) invalid();
    const array = Array.isArray(value);
    const prototype = Object.getPrototypeOf(value);
    if (array ? prototype !== Array.prototype : prototype !== Object.prototype && prototype !== null) invalid();
    if (Object.getOwnPropertySymbols(value).length !== 0) invalid();
    const descriptors = Object.getOwnPropertyDescriptors(value);
    const names = Object.keys(descriptors);
    if (names.length > JSON_MAX_INPUT_NODES - nodes) limit();
    active.add(value);
    count("{}"); // Container delimiters have the same byte count for arrays.
    if (array) {
      if (value.length > JSON_MAX_INPUT_NODES - nodes || names.length !== value.length + 1) invalid();
      const result: unknown[] = [];
      for (let i = 0; i < value.length; i++) {
        const descriptor = descriptors[String(i)];
        if (!descriptor || !descriptor.enumerable || !("value" in descriptor)) invalid();
        if (i > 0) count(",");
        result.push(copy(descriptor.value, depth + 1));
      }
      active.delete(value);
      return result;
    }
    const result = Object.create(null) as Record<string, unknown>;
    for (let i = 0; i < names.length; i++) {
      const name = names[i]!;
      const descriptor = descriptors[name]!;
      if (!descriptor.enumerable || !("value" in descriptor)) invalid();
      if (i > 0) count(",");
      string(name);
      count(":");
      result[name] = copy(descriptor.value, depth + 1);
    }
    active.delete(value);
    return result;
  };
  return copy(input, 0);
}

