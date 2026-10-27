import { Ajv2020 } from 'ajv/dist/2020.js';
import schema from '../../../schemas/framework-pack.v1.json' with { type: 'json' };
import { snapshotJsonData } from '../../json-snapshot.js';
import { parseRuntimeYaml } from '../target.js';

export type PackLanguage = 'java' | 'kotlin';
export type PackSource = { annotation: string[] } | { call: string[] };
export type PackSurface = { provider: 'spring-actuator' } | { provider: 'openapi'; paths: string[] }
  | { provider: 'source-routes'; annotations: string[] };
export interface PackSink { call: string[]; arg: number }
export interface PackSanitizer {
  call: string[]; when: { argCount: '>=2' | '>=3' | '>=4' | '>=5' | '>=6' | '>=7' | '>=8'; placeholders: true };
}
export interface FrameworkPack {
  id: string; version: number; languages: PackLanguage[];
  detect: { anyFile: string[]; contains: string[] };
  runtime: { profile: 'jvm'; env: Record<string, string>; defaultPort: number; health: string };
  surfaces: PackSurface[]; sources: PackSource[];
  sinks: { sql: PackSink[] }; sanitizers: { sql: PackSanitizer[] };
}

function invalid(): never { throw new TypeError('invalid_framework_pack'); }
const ajv = new Ajv2020({
  strict: true, allErrors: false, $data: false, coerceTypes: false, useDefaults: false,
  removeAdditional: false, ownProperties: true, validateSchema: true, logger: false,
});
const validate = ajv.compile<FrameworkPack>(schema);
const interpolation = /\$(?:\$?[{(]|[A-Za-z_])|%[A-Za-z_][A-Za-z0-9_]*%/;
const processEnv = new Set(['PATH', 'HOME', 'TMPDIR', 'ENV', 'BASH_ENV', 'CLASSPATH', 'JAVA_HOME',
  'JAVA_TOOL_OPTIONS', 'JDK_JAVA_OPTIONS', 'NODE_OPTIONS', 'NODE_PATH', 'PYTHONPATH', 'PYTHONHOME',
  'RUBYOPT', 'PERL5OPT']);
const keywords = new Set(('abstract assert boolean break byte case catch char class const continue default do double '
  + 'else enum extends final finally float for goto if implements import instanceof int interface long native new '
  + 'package private protected public return short static strictfp super switch synchronized this throw throws '
  + 'transient try void volatile while true false null fun val var when object typealias is in as typeof').split(' '));

/** Schema-valid data is neither execution authority nor a claim that every reserved feature is implemented. */
export function parseFrameworkPack(input: unknown): FrameworkPack {
  try {
    // Ajv's uniqueItems comparator expects ordinary JSON objects, not null-prototype maps.
    // Snapshot first: this round trip can invoke no caller getter/toJSON/proxy.
    const data: unknown = JSON.parse(JSON.stringify(snapshotJsonData(input, invalid, invalid)));
    if (!validate(data)) invalid();
    if (Object.keys(data.runtime.env).some(key => processEnv.has(key) || /^(?:LD_|DYLD_)/.test(key)
      || /(?:PROXY|TOKEN|SECRET|PASSWORD|CREDENTIAL)/.test(key))) invalid();
    const symbols = data.sources.flatMap(source => 'call' in source ? source.call : source.annotation)
      .concat(data.sinks.sql.flatMap(sink => sink.call), data.sanitizers.sql.flatMap(hint => hint.call),
        data.surfaces.flatMap(surface => surface.provider === 'source-routes' ? surface.annotations : []));
    if (symbols.some(symbol => symbol.replace(/\*$/, '').split('.').some(part => keywords.has(part)))) invalid();
    const pending: unknown[] = [data];
    while (pending.length) {
      const value = pending.pop();
      if (typeof value === 'string' && interpolation.test(value)) invalid();
      if (value && typeof value === 'object') {
        for (const [key, child] of Object.entries(value)) {
          if (interpolation.test(key)) invalid(); pending.push(child);
        }
      }
    }
    return data;
  } catch { return invalid(); }
}

export function parseFrameworkPackYaml(text: string): FrameworkPack {
  try { return parseFrameworkPack(parseRuntimeYaml(text)); } catch { return invalid(); }
}
