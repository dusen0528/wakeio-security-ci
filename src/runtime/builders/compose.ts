import { createHash } from 'node:crypto';
import metadata from '../../../workers/runtime-build/profiles.json' with { type: 'json' };
import { snapshotJsonData } from '../../json-snapshot.js';
import { parseRuntimeYaml, parseTargetYaml } from '../target.js';
import type { TargetSpec } from '../types.js';
import { normaliseCompose } from './compose-input.js';
import type { NormalizedComposeInput } from './compose-input.js';

type ReadonlyData<T> = T extends readonly (infer Item)[]
  ? readonly ReadonlyData<Item>[]
  : T extends object ? { readonly [Key in keyof T]: ReadonlyData<T[Key]> } : T;

export interface ProfileFileBinding {
  readonly path: string;
  readonly repositoryPath: string;
  readonly bytes: number;
  readonly sha256: string;
}

/** Expected data bindings, not proof of a read, capture, build or runtime qualification. */
export interface FixedComposeSelection {
  readonly kind: 'DATA';
  readonly executable: false;
  readonly profileId: string;
  readonly sourceRoot: string;
  readonly build: readonly ProfileFileBinding[];
  readonly scanner: readonly ProfileFileBinding[];
  readonly controllerOnly: readonly ProfileFileBinding[];
  readonly target: ReadonlyData<TargetSpec>;
  readonly compose: ReadonlyData<NormalizedComposeInput>;
  readonly pins: ReadonlyData<typeof metadata.pins>;
  readonly commands: ReadonlyData<typeof metadata.commands>;
  readonly restrictions: ReadonlyData<typeof metadata.restrictions>;
}

export class FixedComposeProfileError extends TypeError {
  readonly code = 'invalid_fixed_compose_profile';
  constructor() {
    super('invalid_fixed_compose_profile');
    this.name = 'FixedComposeProfileError';
  }
}

function invalid(): never {
  throw new FixedComposeProfileError();
}

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function verifyText(
  value: unknown,
  binding: { readonly bytes: number; readonly sha256: string },
): asserts value is string {
  if (typeof value !== 'string' || value.length > binding.bytes
    || Buffer.byteLength(value, 'utf8') !== binding.bytes
    || Buffer.from(value, 'utf8').toString('utf8') !== value
    || createHash('sha256').update(value, 'utf8').digest('hex') !== binding.sha256) invalid();
}

// Only locally constructed data reaches this function, never caller-owned objects or accessors.
function freezeData(value: unknown): void {
  if (value === null || typeof value !== 'object') return;
  for (const child of Object.values(value)) freezeData(child);
  Object.freeze(value);
}

freezeData(metadata);

/**
 * Accept exactly {profileId, sourceRoot, targetText, composeText, pinsText} as bounded own data.
 * Controller bytes must match before parsing. Source files remain expected bindings for later
 * canonical capture; this selector performs no I/O and supplies no execution authority.
 */
export function selectFixedComposeProfile(input: unknown): FixedComposeSelection {
  const data = snapshotJsonData(input, invalid, invalid);
  const keys = ['profileId', 'sourceRoot', 'targetText', 'composeText', 'pinsText'] as const;
  if (!record(data) || Object.keys(data).length !== keys.length
    || keys.some(key => !Object.hasOwn(data, key))) invalid();
  const profile = metadata.profiles.find(item => item.id === data['profileId']);
  if (!profile || data['sourceRoot'] !== profile.root) invalid();
  const files = profile.files.map(index => {
    const binding = metadata.bindings[index];
    if (!binding) invalid();
    return { ...binding, repositoryPath: `${profile.root}/${binding.path}` };
  });
  const targetBinding = files.find(file => file.path === 'wakeio.target.yml');
  const composeBinding = files.find(file => file.path === 'compose.json');
  if (!targetBinding || !composeBinding) invalid();
  const targetText = data['targetText'], composeText = data['composeText'], pinsText = data['pinsText'];
  verifyText(targetText, targetBinding);
  verifyText(composeText, composeBinding);
  verifyText(pinsText, metadata.pinsBinding);
  const target = parseTargetYaml(targetText);
  const compose = normaliseCompose(parseRuntimeYaml(composeText), target);
  const pins = parseRuntimeYaml(pinsText);
  if (!record(pins) || JSON.stringify(pins['baseImages']) !== JSON.stringify(metadata.pins.baseImages)) invalid();
  const selection: FixedComposeSelection = {
    kind: 'DATA', executable: false, profileId: profile.id, sourceRoot: profile.root,
    build: files.filter(file => file.roles.includes('BUILD')),
    scanner: files.filter(file => file.roles.includes('SCANNER')),
    controllerOnly: [
      ...files.filter(file => file.roles.includes('CONTROLLER_ONLY')),
      { path: 'pins.json', repositoryPath: profile.pinsPath, ...metadata.pinsBinding },
    ],
    target, compose, pins: metadata.pins, commands: metadata.commands, restrictions: metadata.restrictions,
  };
  freezeData(selection);
  return selection;
}
