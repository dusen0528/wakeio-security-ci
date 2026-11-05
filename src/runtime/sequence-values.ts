import { snapshotJsonData } from '../json-snapshot.js';
import { assertNever, fail } from './sequence-domain.js';
import type {
  Destination, ExtractionDeclaration, IssueLocation, ScalarType, SequenceScalar,
} from './sequence-domain.js';

/** Decoded segments, never a slash-joined identity. */
export function pointerSegments(pointer: string, location: IssueLocation): readonly string[] {
  if (Buffer.byteLength(pointer, 'utf8') > 512 || /[\u0000-\u001f\u007f]/.test(pointer)
    || pointer !== '' && !pointer.startsWith('/')) fail('invalid_pointer', location);
  const segments = pointer === '' ? [] : pointer.slice(1).split('/');
  if (segments.length > 16) fail('invalid_pointer', location);
  return segments.map(segment => {
    if (/~(?![01])/.test(segment)) fail('invalid_pointer', location);
    const decoded = segment.replace(/~1/g, '/').replace(/~0/g, '~');
    if (['__proto__', 'prototype', 'constructor', '*'].includes(decoded)) fail('invalid_pointer', location);
    return decoded;
  });
}
export function destinationIdentity(destination: Destination, location: IssueLocation): string {
  switch (destination.location) {
    case 'body': return JSON.stringify(['body', pointerSegments(destination.pointer, location)]);
    case 'path': case 'query': case 'header': case 'cookie':
      return JSON.stringify([destination.location, destination.name]);
    default: return assertNever(destination);
  }
}
export function overlap(destinations: readonly Destination[], location: IssueLocation): void {
  const bodies: readonly string[][] = destinations.flatMap(destination => {
    switch (destination.location) {
      case 'body': return [[...pointerSegments(destination.pointer, location)]];
      case 'path': case 'query': case 'header': case 'cookie': return [];
      default: return assertNever(destination);
    }
  });
  for (let i = 0; i < bodies.length; i++) for (let j = 0; j < i; j++) {
    const a = bodies[i], b = bodies[j];
    if (a && b && (a.every((segment, n) => b[n] === segment)
      || b.every((segment, n) => a[n] === segment))) fail('binding_forbidden', location);
  }
}
export function typedScalar(raw: unknown, type: ScalarType, location: IssueLocation): SequenceScalar {
  switch (type) {
    case 'string':
      if (typeof raw !== 'string') return fail('type_mismatch', location);
      return { scalarType: type, value: raw };
    case 'number':
      if (typeof raw !== 'number' || !Number.isFinite(raw)) return fail('type_mismatch', location);
      return { scalarType: type, value: raw };
    case 'boolean':
      if (typeof raw !== 'boolean') return fail('type_mismatch', location);
      return { scalarType: type, value: raw };
    case 'null':
      if (raw !== null) return fail('type_mismatch', location);
      return { scalarType: type, value: raw };
    default: return assertNever(type);
  }
}
export function scalarBytes(value: SequenceScalar, maxBytes: number, location: IssueLocation): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 4096
    || Buffer.byteLength(JSON.stringify(value.value), 'utf8') > maxBytes) fail('extraction_limit', location);
}
export function extractScalar(raw: unknown, declaration: ExtractionDeclaration): SequenceScalar {
  const location = { field: 'extraction' } as const;
  let value = snapshotJsonData(raw, () => fail('invalid_shape', location), () => fail('input_limit', location));
  for (const segment of pointerSegments(declaration.pointer, location)) {
    if (Array.isArray(value)) {
      if (!/^(?:0|[1-9][0-9]*)(?![\s\S])/.test(segment)
        || !Number.isSafeInteger(Number(segment))) fail('invalid_pointer', location);
      if (Number(segment) >= value.length) fail('extraction_missing', location);
      value = value[Number(segment)];
    } else {
      if (value === null || typeof value !== 'object' || !Object.hasOwn(value, segment)) {
        fail('extraction_missing', location);
      }
      const descriptor = Object.getOwnPropertyDescriptor(value, segment);
      if (!descriptor || !('value' in descriptor)) fail('extraction_missing', location);
      value = descriptor.value;
    }
  }
  const result = typedScalar(value, declaration.scalarType, location);
  scalarBytes(result, declaration.maxBytes, location);
  return Object.freeze(result);
}
