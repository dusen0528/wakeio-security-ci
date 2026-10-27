const ALIAS = /^[a-z][a-z0-9_-]{0,39}$/;

export function fail(): never { throw new TypeError('invalid_execution_plan'); }

export function keys(value: Record<string, unknown>, required: string[], optional: string[] = []): void {
  if (required.some(key => !Object.hasOwn(value, key))
    || Object.keys(value).some(key => !required.includes(key) && !optional.includes(key))) fail();
}

export function alias(value: unknown): asserts value is string {
  if (typeof value !== 'string' || !ALIAS.test(value)) fail();
}

export function count(value: unknown, max: number): asserts value is number {
  if (!Number.isSafeInteger(value) || Number(value) < 1 || Number(value) > max) fail();
}
