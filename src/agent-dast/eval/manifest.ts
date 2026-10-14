/**
 * Run-start record for one A-vs-B comparison.
 *
 * Written before the arms run, it pins three hashes into one record:
 *
 *   - the pass criteria,
 *   - the final label set,
 *   - the shared check list both arms must run.
 *
 * Results then reference this record by its digest, and each scored finding
 * references its run.db / evidence file. If any of the three inputs is edited
 * after the record is written, the digest changes and the comparison refuses
 * the results.
 *
 * This does not by itself prove *when* the record was written — that timestamp
 * / signature binding is the follow-up execution layer's job (see the design
 * doc). What it does guarantee offline, from stored results, is that the
 * criteria, labels and check list a result claims are exactly the ones fixed
 * at run start, and that every scored finding points at recorded evidence.
 */
import { createHash } from 'node:crypto';
import type { FinalLabels } from './labels.js';
import type { PassCriteria } from './aggregate.js';

export const CHECK_ID = /^c-[0-9a-z][0-9a-z-]{0,48}$/;
export const ENGINES = ['native-dast', 'schemathesis', 'nuclei'] as const;
export type Engine = typeof ENGINES[number];

/** One check in the shared list both arms run. The list is the agreed scope. */
export interface ChecklistEntry {
  checkId: string;
  engine: Engine;
  /** Engine-local check name, e.g. a policy or template-scope identifier. */
  check: string;
}

export interface Checklist {
  version: 1;
  entries: ChecklistEntry[];
}

export class ManifestError extends Error {
  constructor(readonly code: 'checklist_invalid' | 'manifest_invalid' | 'criteria_label_mismatch' | 'digest_mismatch' | 'field_mismatch', detail?: string) {
    super(detail ? `${code}: ${detail}` : code);
  }
}

function canonical(value: unknown): string { return JSON.stringify(value); }
function sha256(value: unknown): string { return createHash('sha256').update(canonical(value)).digest('hex'); }

export function parseChecklist(raw: unknown): Checklist {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new ManifestError('checklist_invalid', '$');
  const r = raw as Record<string, unknown>;
  if (r.version !== 1 || !Array.isArray(r.entries) || r.entries.length === 0) throw new ManifestError('checklist_invalid', '$.entries');
  const seen = new Set<string>();
  const entries = r.entries.map((e, i): ChecklistEntry => {
    const p = `$.entries[${i}]`;
    if (e === null || typeof e !== 'object' || Array.isArray(e)) throw new ManifestError('checklist_invalid', p);
    const entry = e as Record<string, unknown>;
    if (typeof entry.checkId !== 'string' || !CHECK_ID.test(entry.checkId)) throw new ManifestError('checklist_invalid', `${p}.checkId`);
    if (seen.has(entry.checkId)) throw new ManifestError('checklist_invalid', `${p}.checkId`);
    seen.add(entry.checkId);
    if (typeof entry.engine !== 'string' || !(ENGINES as readonly string[]).includes(entry.engine)) throw new ManifestError('checklist_invalid', `${p}.engine`);
    if (typeof entry.check !== 'string' || !entry.check || entry.check.length > 200) throw new ManifestError('checklist_invalid', `${p}.check`);
    return { checkId: entry.checkId, engine: entry.engine as Engine, check: entry.check };
  });
  return { version: 1, entries };
}

/** Order-independent hash of the shared check list. */
export function checklistHash(list: Checklist): string {
  const sorted = [...list.entries].sort((a, b) => a.checkId < b.checkId ? -1 : 1).map(e => [e.checkId, e.engine, e.check]);
  return sha256({ checklist: sorted });
}

/** Hash of the pass criteria exactly as committed. */
export function criteriaHash(criteria: PassCriteria): string {
  return sha256({ version: criteria.version, labelSetHash: criteria.labelSetHash, committedBeforeArmB: criteria.committedBeforeArmB, sharedRequestCap: criteria.sharedRequestCap, basis: criteria.basis });
}

/**
 * One coverage cell fixed before the run: a surface crossed with a check from
 * the shared list. The count of cells is the coverage denominator both arms
 * must use, so the denominator is tied to the check list and cannot be set to
 * an arbitrary number.
 */
export interface CoverageCell {
  /** Surface identity key (e.g. method+path+param+auth). Opaque to this layer. */
  surface: string;
  checkId: string;
}

export interface RunManifest {
  version: 1;
  runId: string;
  /** Declared creation time. Unverified here; the execution layer binds it. */
  createdAt: string;
  target: string;
  commit: string;
  criteriaHash: string;
  finalLabelHash: string;
  checklistHash: string;
  /** Coverage cells fixed at run start; their count is the shared denominator. */
  coverageCells: CoverageCell[];
  sharedRequestCap: number;
  basis: PassCriteria['basis'];
}

function parseCoverageCells(raw: unknown, checkIds: ReadonlySet<string>): CoverageCell[] {
  if (!Array.isArray(raw) || raw.length === 0) throw new ManifestError('manifest_invalid', 'coverageCells');
  const seen = new Set<string>();
  return raw.map((c, i): CoverageCell => {
    const p = `coverageCells[${i}]`;
    if (c === null || typeof c !== 'object' || Array.isArray(c)) throw new ManifestError('manifest_invalid', p);
    const cell = c as Record<string, unknown>;
    if (typeof cell.surface !== 'string' || !cell.surface || cell.surface.length > 512) throw new ManifestError('manifest_invalid', `${p}.surface`);
    if (typeof cell.checkId !== 'string' || !CHECK_ID.test(cell.checkId)) throw new ManifestError('manifest_invalid', `${p}.checkId`);
    // Every coverage cell must name a check from the shared list.
    if (!checkIds.has(cell.checkId)) throw new ManifestError('manifest_invalid', `${p}.checkId not in checklist`);
    const key = `${cell.surface}\u0000${cell.checkId}`;
    if (seen.has(key)) throw new ManifestError('manifest_invalid', `${p} duplicate`);
    seen.add(key);
    return { surface: cell.surface, checkId: cell.checkId };
  });
}

function sortedCells(cells: readonly CoverageCell[]): CoverageCell[] {
  return [...cells].sort((a, b) => (a.surface === b.surface ? (a.checkId < b.checkId ? -1 : 1) : a.surface < b.surface ? -1 : 1));
}

export interface BuildManifestInput {
  runId: string;
  createdAt: string;
  labels: FinalLabels;
  criteria: PassCriteria;
  checklist: Checklist;
  coverageCells: CoverageCell[];
}

/** Build the run-start record, cross-checking that criteria already bind these labels. */
export function buildRunManifest(input: BuildManifestInput): RunManifest {
  if (!/^run-[0-9a-z][0-9a-z-]{0,48}$/.test(input.runId)) throw new ManifestError('manifest_invalid', 'runId');
  if (typeof input.createdAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(input.createdAt)) throw new ManifestError('manifest_invalid', 'createdAt');
  if (input.criteria.labelSetHash !== input.labels.hash) throw new ManifestError('criteria_label_mismatch', `criteria ${input.criteria.labelSetHash.slice(0, 12)} vs labels ${input.labels.hash.slice(0, 12)}`);
  const checkIds = new Set(input.checklist.entries.map(e => e.checkId));
  const coverageCells = sortedCells(parseCoverageCells(input.coverageCells, checkIds));
  return {
    version: 1,
    runId: input.runId,
    createdAt: input.createdAt,
    target: input.labels.target,
    commit: input.labels.commit,
    criteriaHash: criteriaHash(input.criteria),
    finalLabelHash: input.labels.hash,
    checklistHash: checklistHash(input.checklist),
    coverageCells,
    sharedRequestCap: input.criteria.sharedRequestCap,
    basis: input.criteria.basis,
  };
}

/** Digest the whole record; results reference this value. */
export function manifestDigest(manifest: RunManifest): string {
  return sha256([
    manifest.version, manifest.runId, manifest.createdAt, manifest.target, manifest.commit,
    manifest.criteriaHash, manifest.finalLabelHash, manifest.checklistHash,
    sortedCells(manifest.coverageCells).map(c => [c.surface, c.checkId]),
    manifest.sharedRequestCap, manifest.basis,
  ]);
}

export function parseRunManifest(raw: unknown): RunManifest {
  if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) throw new ManifestError('manifest_invalid', '$');
  const r = raw as Record<string, unknown>;
  const hex = (key: string) => { const v = r[key]; if (typeof v !== 'string' || !/^[0-9a-f]{64}$/.test(v)) throw new ManifestError('manifest_invalid', key); return v; };
  if (r.version !== 1) throw new ManifestError('manifest_invalid', 'version');
  if (typeof r.runId !== 'string' || !/^run-[0-9a-z][0-9a-z-]{0,48}$/.test(r.runId)) throw new ManifestError('manifest_invalid', 'runId');
  if (typeof r.createdAt !== 'string' || !/^\d{4}-\d{2}-\d{2}T/.test(r.createdAt)) throw new ManifestError('manifest_invalid', 'createdAt');
  if (typeof r.target !== 'string' || !r.target) throw new ManifestError('manifest_invalid', 'target');
  if (typeof r.commit !== 'string' || !/^[0-9a-f]{7,64}$/.test(r.commit)) throw new ManifestError('manifest_invalid', 'commit');
  if (!Number.isSafeInteger(r.sharedRequestCap) || (r.sharedRequestCap as number) < 1) throw new ManifestError('manifest_invalid', 'sharedRequestCap');
  if (r.basis !== 'candidate' && r.basis !== 'confirmed') throw new ManifestError('manifest_invalid', 'basis');
  // Cells are validated against the check list in verifyManifest; shape-check only here.
  if (!Array.isArray(r.coverageCells) || r.coverageCells.length === 0) throw new ManifestError('manifest_invalid', 'coverageCells');
  const coverageCells = r.coverageCells.map((c, i): CoverageCell => {
    const cell = c as Record<string, unknown>;
    if (cell === null || typeof cell !== 'object' || typeof cell.surface !== 'string' || !cell.surface || cell.surface.length > 512 || typeof cell.checkId !== 'string' || !CHECK_ID.test(cell.checkId)) throw new ManifestError('manifest_invalid', `coverageCells[${i}]`);
    return { surface: cell.surface, checkId: cell.checkId };
  });
  return {
    version: 1, runId: r.runId, createdAt: r.createdAt, target: r.target, commit: r.commit,
    criteriaHash: hex('criteriaHash'), finalLabelHash: hex('finalLabelHash'), checklistHash: hex('checklistHash'),
    coverageCells,
    sharedRequestCap: r.sharedRequestCap as number, basis: r.basis,
  };
}

/**
 * Recompute the manifest's three hashes from the criteria, labels and check
 * list a result supplies, and confirm the record and its digest are untampered.
 * Any edited input changes a hash and throws.
 */
export function verifyManifest(manifest: RunManifest, expectedDigest: string, inputs: { labels: FinalLabels; criteria: PassCriteria; checklist: Checklist }): void {
  if (manifestDigest(manifest) !== expectedDigest) throw new ManifestError('digest_mismatch', 'manifest digest does not match the referenced digest');
  if (manifest.finalLabelHash !== inputs.labels.hash) throw new ManifestError('digest_mismatch', 'final label hash');
  if (manifest.criteriaHash !== criteriaHash(inputs.criteria)) throw new ManifestError('digest_mismatch', 'criteria hash');
  if (manifest.checklistHash !== checklistHash(inputs.checklist)) throw new ManifestError('digest_mismatch', 'checklist hash');
  if (inputs.criteria.labelSetHash !== inputs.labels.hash) throw new ManifestError('criteria_label_mismatch', 'criteria do not bind these labels');
  // A matching digest proves the record is self-consistent, not that its plain
  // fields agree with the inputs. Cross-check the fields the digest covers but
  // nothing else re-derives, or an internally consistent but wrong record passes.
  if (manifest.target !== inputs.labels.target) throw new ManifestError('field_mismatch', `target ${manifest.target} vs labels ${inputs.labels.target}`);
  if (manifest.commit !== inputs.labels.commit) throw new ManifestError('field_mismatch', `commit ${manifest.commit} vs labels ${inputs.labels.commit}`);
  if (manifest.sharedRequestCap !== inputs.criteria.sharedRequestCap) throw new ManifestError('field_mismatch', `sharedRequestCap ${manifest.sharedRequestCap} vs criteria ${inputs.criteria.sharedRequestCap}`);
  if (manifest.basis !== inputs.criteria.basis) throw new ManifestError('field_mismatch', `basis ${manifest.basis} vs criteria ${inputs.criteria.basis}`);
  // Every coverage cell must name a check from the shared list.
  const checkIds = new Set(inputs.checklist.entries.map(e => e.checkId));
  for (const cell of manifest.coverageCells) {
    if (!checkIds.has(cell.checkId)) throw new ManifestError('field_mismatch', `coverage cell check ${cell.checkId} not in checklist`);
  }
}
