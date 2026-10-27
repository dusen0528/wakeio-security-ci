import { Ajv2020 } from 'ajv/dist/2020.js';
import { CST, Lexer, isAlias, isMap, isNode, isScalar, isSeq, parseDocument } from 'yaml';
import schema from '../../schemas/target.v1.json' with { type: 'json' };
import { JSON_MAX_DEPTH, JSON_MAX_INPUT_BYTES, JSON_MAX_INPUT_NODES, snapshotJsonData }
  from '../json-snapshot.js';
import type { TargetSpec } from './types.js';

function invalid(): never { throw new TypeError('invalid_runtime_target'); }
const interpolation = /\$(?:\$?[{(]|[A-Za-z_])|%[A-Za-z_][A-Za-z0-9_]*%/;

/** Inspect YAML nodes before conversion: no tags, references, merges or expanded input. */
function checkNodes(root: unknown): void {
  const pending = [{ node: root, depth: 0 }]; let count = 0;
  while (pending.length) {
    const { node, depth } = pending.pop()!;
    if (++count > JSON_MAX_INPUT_NODES || depth > JSON_MAX_DEPTH) invalid();
    if (node === null) continue;
    if (!isNode(node) || isAlias(node) || node.tag || node.anchor) invalid();
    if (isScalar(node)) {
      if (typeof node.value === 'string' && interpolation.test(node.value)) invalid();
      if (typeof node.value === 'number' && (!Number.isFinite(node.value)
        || Number.isInteger(node.value) && !Number.isSafeInteger(node.value))) invalid();
    } else if (isMap(node)) {
      for (const pair of node.items) {
        if (!isScalar(pair.key) || typeof pair.key.value !== 'string' || pair.key.value === '<<') invalid();
        pending.push({ node: pair.key, depth: depth + 1 }, { node: pair.value, depth: depth + 1 });
      }
    } else if (isSeq(node)) {
      for (const item of node.items) pending.push({ node: item, depth: depth + 1 });
    } else invalid();
  }
}

/** Pure data only. Raw UTF-8 hashing, stable file reads and consent belong to the I/O caller. */
export function parseRuntimeYaml(text: string): unknown {
  try {
    if (typeof text !== 'string' || text.length > JSON_MAX_INPUT_BYTES
      || Buffer.byteLength(text, 'utf8') > JSON_MAX_INPUT_BYTES
      || Buffer.from(text, 'utf8').toString('utf8') !== text) invalid();
    let scalarBody = false;
    for (const token of new Lexer().lex(text)) {
      if (scalarBody) { scalarBody = false; continue; }
      if (token === CST.SCALAR) scalarBody = true;
      else if (CST.tokenType(token) === 'directive-line') invalid();
    }
    const doc = parseDocument(text, {
      version: '1.2', schema: 'core', strict: true, uniqueKeys: true, stringKeys: true,
      merge: false, resolveKnownTags: false, customTags: [], prettyErrors: false, logLevel: 'error',
    });
    if (doc.errors.length || doc.warnings.length || doc.contents === null
      || doc.directives?.yaml.explicit || Object.keys(doc.directives?.tags ?? {}).some(key => key !== '!!')) {
      invalid();
    }
    if (isScalar(doc.contents) && doc.contents.type === 'PLAIN' && doc.contents.source === '') invalid();
    checkNodes(doc.contents);
    return snapshotJsonData(doc.toJS({ mapAsMap: false, maxAliasCount: 0 }), invalid, invalid);
  } catch { return invalid(); }
}

// Only this bundled, trusted schema is compiled. No loader, caller schema, custom keyword or format.
const ajv = new Ajv2020({
  strict: true, allErrors: false, $data: false, coerceTypes: false, useDefaults: false,
  removeAdditional: false, ownProperties: true, validateSchema: true, logger: false,
});
const validate = ajv.compile<TargetSpec>(schema);

/** Own bounded JSON only: Ajv uniqueItems expects ordinary objects; preserve the original snapshot. */
function validateSnapshot(data: unknown): data is TargetSpec {
  return validate(JSON.parse(JSON.stringify(data)));
}

/** Snapshot own JSON data first; validation grants no file, build, network or execution authority. */
export function parseTargetSpec(input: unknown): TargetSpec {
  try {
    const data = snapshotJsonData(input, invalid, invalid);
    if (!validateSnapshot(data) || data.dependencies.some(value => value.service === data.build.service)) invalid();
    return data;
  } catch { return invalid(); }
}

export function parseTargetYaml(text: string): TargetSpec { return parseTargetSpec(parseRuntimeYaml(text)); }
