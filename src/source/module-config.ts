import * as ts from 'typescript';
import { posix } from 'node:path';
import type { CollectedFile } from './types.js';

const MAX_CONFIG_BYTES = 64 * 1024;
const MAX_CONFIGS = 128;
const MAX_TOTAL_CONFIG_BYTES = 1024 * 1024;
interface Mapping { key: string; prefix?: string; suffix?: string; target: string }
interface Configuration { path: string; base: string; mappings: Mapping[]; supported: boolean }
export type ConfiguredPath = { kind: 'mapped'; path: string } | { kind: 'external' | 'unsupported' };
function object(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
function boundedPath(base: string, value: string): string | undefined {
  if (!value || value.includes('\\') || /[\u0000-\u001f\u007f]/.test(value) || posix.isAbsolute(value)) return undefined;
  const path = posix.normalize(posix.join(base, value));
  return path === '..' || path.startsWith('../') || posix.isAbsolute(path) ? undefined : path;
}

/** Snapshot data only. No compiler plugin, extends, filesystem or package resolution. */
export class ModuleConfigurations {
  private readonly configurations = new Map<string, Configuration>();
  private complete = true;
  readonly observed: number;
  supported = 0; unsupported = 0; bytes = 0;
  constructor(metadata: readonly CollectedFile[], private readonly tick: () => boolean) {
    const files: CollectedFile[] = [];
    for (const file of metadata) {
      if (!this.tick()) { this.complete = false; break; }
      if (['tsconfig.json', 'jsconfig.json'].includes(posix.basename(file.path))) files.push(file);
    }
    this.observed = files.length;
    if (files.length > MAX_CONFIGS) { this.complete = false; this.unsupported = files.length; return; }
    for (const file of files) {
      if (!this.tick()) { this.complete = false; break; }
      const configuration: Configuration = { path: file.path, base: posix.dirname(file.path), mappings: [], supported: false };
      const duplicate = this.configurations.get(file.path);
      if (duplicate) {
        if (duplicate.supported) { this.supported--; this.unsupported++; }
        duplicate.supported = false; this.unsupported++; continue;
      }
      this.configurations.set(file.path, configuration);
      const bytes = Buffer.byteLength(file.text);
      this.bytes += bytes;
      if (bytes > MAX_CONFIG_BYTES || this.bytes > MAX_TOTAL_CONFIG_BYTES) { this.unsupported++; continue; }
      // Charge bounded metadata parse work independently of the common source AST walk.
      let charged = true;
      for (let offset = 0; offset < bytes; offset += 64) if (!this.tick()) { charged = false; this.complete = false; break; }
      if (!charged) break;
      const parsed = ts.parseConfigFileTextToJson(file.path, file.text);
      const data: unknown = parsed.config;
      const options = object(data) && Object.hasOwn(data, 'compilerOptions') && object(data.compilerOptions) ? data.compilerOptions : undefined;
      if (parsed.error || !object(data) || Object.hasOwn(data, 'extends') || Object.hasOwn(data, 'references')
        || Object.hasOwn(data, 'compilerOptions') && !options
        || options && ['rootDirs', 'moduleSuffixes'].some(key => Object.hasOwn(options, key))) { this.unsupported++; continue; }
      if (options?.baseUrl !== undefined) {
        const base = typeof options.baseUrl === 'string' ? boundedPath(posix.dirname(file.path), options.baseUrl) : undefined;
        if (base === undefined) { this.unsupported++; continue; }
        configuration.base = base;
      }
      if (options?.paths !== undefined && !object(options.paths)) { this.unsupported++; continue; }
      let valid = true;
      for (const [key, values] of Object.entries(options?.paths ?? {})) {
        if (!this.tick()) { valid = false; this.complete = false; break; }
        if (!key || key.includes('\\') || key.startsWith('.') || key.startsWith('/') || /[\u0000-\u001f\u007f]/.test(key)
          || key.split('*').length > 2 || !Array.isArray(values) || values.length !== 1
          || typeof values[0] !== 'string' || values[0].split('*').length > 2) { valid = false; break; }
        const target = values[0];
        if (boundedPath(configuration.base, target.replace('*', 'owned')) === undefined) { valid = false; break; }
        const star = key.indexOf('*');
        configuration.mappings.push(star < 0 ? { key, target } : { key, target, prefix: key.slice(0, star), suffix: key.slice(star + 1) });
      }
      configuration.supported = valid;
      if (valid) this.supported++; else this.unsupported++;
    }
  }
  resolve(file: string, specifier: string): ConfiguredPath {
    if (!this.complete) return { kind: 'unsupported' };
    if (!this.configurations.size) return { kind: 'external' };
    if (file.startsWith('/') || file.includes('\\') || file === '..' || file.startsWith('../')) return { kind: 'unsupported' };
    let directory = posix.dirname(file), configuration: Configuration | undefined;
    for (;;) {
      if (!this.tick()) return { kind: 'unsupported' };
      const prefix = directory === '.' ? '' : directory + '/';
      configuration = this.configurations.get(prefix + 'tsconfig.json') ?? this.configurations.get(prefix + 'jsconfig.json');
      if (configuration || directory === '.') break;
      directory = posix.dirname(directory);
    }
    if (!configuration) return { kind: 'external' };
    if (!configuration.supported) return { kind: 'unsupported' };
    // TS 5.9: exact key first, then longest matching prefix; ties preserve key order.
    let selected: Mapping | undefined;
    for (const mapping of configuration.mappings) {
      if (!this.tick()) return { kind: 'unsupported' };
      if (mapping.prefix === undefined && mapping.key === specifier) { selected = mapping; break; }
    }
    if (!selected) for (const mapping of configuration.mappings) {
      if (!this.tick()) return { kind: 'unsupported' };
      if (mapping.prefix === undefined || !specifier.startsWith(mapping.prefix) || !specifier.endsWith(mapping.suffix!)
        || specifier.length < mapping.prefix.length + mapping.suffix!.length) continue;
      if (!selected || mapping.prefix.length > selected.prefix!.length) selected = mapping;
    }
    if (!selected) return { kind: 'external' };
    const captured = selected.prefix === undefined ? undefined : specifier.slice(selected.prefix.length, specifier.length - selected.suffix!.length);
    // TS 5.9 does not substitute an empty capture into a target wildcard.
    // Retaining that wildcard below rejects an invented directory body edge.
    const target = captured ? selected.target.replace('*', captured) : selected.target;
    if (target.includes('*')) return { kind: 'unsupported' };
    const path = boundedPath(configuration.base, target);
    return path === undefined ? { kind: 'unsupported' } : { kind: 'mapped', path };
  }
}
