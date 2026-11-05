import { assertNever, fail } from './sequence-domain.js';
import type {
  Count, Destination, ExtractionDeclaration, Identity, IssueCode, IssueLocation,
  CandidateBinding, ScalarType, ScalarValue,
} from './sequence-domain.js';

export function object(raw: unknown, location: IssueLocation): Record<string, unknown> {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) fail('invalid_shape', location);
  return Object.fromEntries(Object.entries(raw));
}
export function closed(value: Record<string, unknown>, required: readonly string[], issue: {
  readonly code: IssueCode; readonly location: IssueLocation;
}): void {
  if (required.some(key => !Object.hasOwn(value, key))
    || Object.keys(value).some(key => !required.includes(key))) fail(issue.code, issue.location);
}
export function text<Tag extends string>(raw: unknown, location: IssueLocation): Identity<Tag> {
  const isText = (value: unknown): value is Identity<Tag> => typeof value === 'string';
  if (!isText(raw)) fail('invalid_shape', location);
  return raw;
}
export function integer<Tag extends string>(raw: unknown, location: IssueLocation): Count<Tag> {
  const isInteger = (value: unknown): value is Count<Tag> =>
    typeof value === 'number' && Number.isSafeInteger(value);
  if (!isInteger(raw)) fail('invalid_shape', location);
  return raw;
}
export function list(raw: unknown, location: IssueLocation): readonly unknown[] {
  if (!Array.isArray(raw)) fail('invalid_shape', location);
  return raw;
}
export function scalarType(raw: unknown, location: IssueLocation): ScalarType {
  switch (raw) {
    case 'string': case 'number': case 'boolean': case 'null': return raw;
    default: return fail('invalid_shape', location);
  }
}
function scalar(raw: unknown, location: IssueLocation): ScalarValue {
  if (raw === null || typeof raw === 'string' || typeof raw === 'boolean'
    || typeof raw === 'number') return raw;
  return fail('invalid_shape', location);
}
function destination(raw: unknown, location: IssueLocation): Destination {
  const value = object(raw, location), issue = { code: 'binding_forbidden', location } as const;
  switch (value.location) {
    case 'body':
      closed(value, ['location', 'pointer'], issue);
      return { location: 'body', pointer: text(value.pointer, location) };
    case 'path': case 'query': case 'header': case 'cookie':
      closed(value, ['location', 'name'], issue);
      return { location: value.location, name: text(value.name, location) };
    default: return fail('binding_forbidden', location);
  }
}
export function binding(raw: unknown, location: IssueLocation): CandidateBinding {
  const value = object(raw, location);
  const common = ['destination', 'kind', 'valueType', 'scalarType'];
  const issue = { code: 'binding_forbidden', location } as const;
  // Check forbidden authority before reading required scalar fields.
  switch (value.kind) {
    case 'literal': closed(value, [...common, 'value'], issue); break;
    case 'extracted': closed(value, [...common, 'producerOrdinal', 'extractionRef'], issue); break;
    case 'actor': closed(value, [...common, 'credentialRef'], issue); break;
    default: return fail('binding_forbidden', location);
  }
  const base = { destination: destination(value.destination, location),
    valueType: text<'value-type'>(value.valueType, location), scalarType: scalarType(value.scalarType, location) };
  switch (value.kind) {
    case 'literal': return { ...base, kind: 'literal', value: scalar(value.value, location) };
    case 'extracted': return { ...base, kind: 'extracted',
      producerOrdinal: integer<'ordinal'>(value.producerOrdinal, location),
      extractionRef: text<'extraction'>(value.extractionRef, location) };
    case 'actor': return { ...base, kind: 'actor', credentialRef: text<'credential'>(value.credentialRef, location) };
    default: return assertNever(value.kind);
  }
}
export function extraction(raw: unknown, location: IssueLocation): ExtractionDeclaration {
  const value = object(raw, location);
  closed(value, ['id', 'pointer', 'scalarType', 'valueType', 'maxBytes'], { code: 'invalid_shape', location });
  const maxBytes = integer<'scalar-bytes'>(value.maxBytes, location);
  if (maxBytes < 1 || maxBytes > 4096) fail('extraction_limit', location);
  return { id: text(value.id, location), pointer: text(value.pointer, location),
    scalarType: scalarType(value.scalarType, location), valueType: text(value.valueType, location), maxBytes };
}
