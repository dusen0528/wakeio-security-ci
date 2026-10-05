import type { AnalysisGap, AnalysisGapReason, AnalysisGapReasonSummary, AnalysisGaps } from './contracts.js';

export const GAP_CHECK_LIMIT = 32;
export const GAP_REPORT_LIMIT = 256;
const REASONS: readonly AnalysisGapReason[] = [
  'module_export_unsupported', 'module_missing', 'module_ambiguous', 'module_module_budget', 'node_limit',
  'index_work_limit', 'flow_work_limit', 'function_limit', 'summary_limit',
  'depth_limit', 'alias_limit', 'summary_cycle', 'parse_error',
];
const SITE_REASONS = new Set<AnalysisGapReason>(['module_export_unsupported', 'module_missing', 'module_ambiguous', 'module_module_budget']);
const safeCount = (n: unknown): n is number => typeof n === 'number' && Number.isSafeInteger(n) && n >= 0;
const add = (a: number, b: number): number | undefined => a > Number.MAX_SAFE_INTEGER - b ? undefined : a + b;
const unknownSummary = (): AnalysisGapReasonSummary => ({ accounting: 'unknown', rows: [] });
const unknown = (items: AnalysisGap[], summaryPresent = false): AnalysisGaps => ({ accounting: 'unknown', items, eventsObserved: null, eventsDropped: null, truncated: true,
  ...(summaryPresent ? { reasonSummary: unknownSummary() } : {}) });
const keyOf = (item: AnalysisGap): string => JSON.stringify([item.reason, item.phase, item.extent, item.location, item.diagnosticCode]);

export function nextGapReview(reason: AnalysisGapReason): AnalysisGap['nextReview'] {
  if (reason === 'module_export_unsupported') return 'review_check_diagnostics';
  if (SITE_REASONS.has(reason)) return 'review_collected_source_context';
  if (reason === 'parse_error') return 'review_parse_diagnostics';
  return reason === 'summary_cycle' ? 'review_check_diagnostics' : 'review_analysis_budget';
}

/** Scan-local diagnostics only: no analysis state, traversal, or execution authority. */
export class AnalysisGapRecorder {
  private readonly items: AnalysisGap[] = [];
  private readonly byKey = new Map<string, AnalysisGap>();
  private observed = 0;
  private dropped = 0;
  private exact = true;
  private readonly reasonObserved = REASONS.map(() => 0);
  private readonly reasonDropped = REASONS.map(() => 0);

  markUnknown(): void { this.exact = false; }

  record(reason: string, phase: AnalysisGap['phase'], location?: AnalysisGap['location'], count = 1, diagnosticCode?: number): void {
    if (!safeCount(count) || count === 0) { if (count !== 0) this.exact = false; return; }
    if (!REASONS.includes(reason as AnalysisGapReason)) { this.exact = false; return; }
    const observed = add(this.observed, count);
    if (observed === undefined) { this.exact = false; return; }
    this.observed = observed;
    const r = reason as AnalysisGapReason;
    const index = REASONS.indexOf(r);
    const reasonObserved = add(this.reasonObserved[index], count);
    if (reasonObserved === undefined) { this.exact = false; return; }
    this.reasonObserved[index] = reasonObserved;
    const parseSite = r === 'parse_error' && phase === 'parse' && !!location;
    if ((parseSite || diagnosticCode !== undefined) && (!parseSite || !safeCount(diagnosticCode) || diagnosticCode === 0)) this.exact = false;
    const site = location && ((SITE_REASONS.has(r) && phase === 'flow') || (parseSite && safeCount(diagnosticCode) && diagnosticCode > 0));
    const item: AnalysisGap = { reason: r, phase, extent: site ? 'site' : 'check', observations: count,
      ...(site ? { location: { ...location } } : {}),
      ...(parseSite && safeCount(diagnosticCode) && diagnosticCode > 0 ? { diagnosticCode } : {}), nextReview: nextGapReview(r) };
    const key = keyOf(item);
    const prior = this.byKey.get(key);
    if (prior) {
      const sum = add(prior.observations, count);
      if (sum === undefined) this.exact = false; else prior.observations = sum;
    } else if (this.items.length < GAP_CHECK_LIMIT) {
      this.items.push(item); this.byKey.set(key, item);
    } else {
      const sum = add(this.dropped, count);
      if (sum === undefined) this.exact = false; else this.dropped = sum;
      const reasonDropped = add(this.reasonDropped[index], count);
      if (reasonDropped === undefined) this.exact = false; else this.reasonDropped[index] = reasonDropped;
    }
  }

  result(): AnalysisGaps | undefined {
    if (this.observed === 0 && this.exact) return undefined;
    const items = this.items.map((item) => ({ ...item, ...(item.location ? { location: { ...item.location } } : {}) }));
    return this.exact ? { accounting: 'exact', items, eventsObserved: this.observed, eventsDropped: this.dropped, truncated: this.dropped > 0,
      reasonSummary: { accounting: 'exact', rows: REASONS.flatMap((reason, index) => this.reasonObserved[index] > 0
        ? [{ reason, eventsObserved: this.reasonObserved[index], eventsDropped: this.reasonDropped[index] }] : []) } } : unknown(items, true);
  }
}

function sanitiseReasonSummary(input: unknown, gaps: AnalysisGaps): AnalysisGapReasonSummary {
  if (gaps.accounting !== 'exact' || !input || typeof input !== 'object' || Array.isArray(input)) return unknownSummary();
  const v = input as Record<string, unknown>;
  if (v.accounting !== 'exact' || !Array.isArray(v.rows) || v.rows.length > REASONS.length) return unknownSummary();
  const rows = new Map<AnalysisGapReason, AnalysisGapReasonSummary['rows'][number]>();
  let observed = 0, dropped = 0;
  for (const raw of v.rows) {
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return unknownSummary();
    const row = raw as Record<string, unknown>, reason = row.reason as AnalysisGapReason;
    if (!REASONS.includes(reason) || rows.has(reason) || !safeCount(row.eventsObserved) || !safeCount(row.eventsDropped)) return unknownSummary();
    const nextObserved = add(observed, row.eventsObserved), nextDropped = add(dropped, row.eventsDropped);
    if (nextObserved === undefined || nextDropped === undefined) return unknownSummary();
    observed = nextObserved; dropped = nextDropped;
    rows.set(reason, { reason, eventsObserved: row.eventsObserved, eventsDropped: row.eventsDropped });
  }
  if (observed !== gaps.eventsObserved || dropped !== gaps.eventsDropped) return unknownSummary();
  for (const reason of REASONS) {
    let retained = 0;
    for (const item of gaps.items) if (item.reason === reason) {
      const sum = add(retained, item.observations); if (sum === undefined) return unknownSummary(); retained = sum;
    }
    const row = rows.get(reason);
    if (add(retained, row?.eventsDropped ?? 0) !== (row?.eventsObserved ?? 0)) return unknownSummary();
  }
  return { accounting: 'exact', rows: REASONS.flatMap(reason => {
    const row = rows.get(reason); return row && row.eventsObserved! > 0 ? [{ ...row }] : [];
  }) };
}

function gapItem(input: unknown, safePath: (value: string) => string | undefined): AnalysisGap | undefined {
  if (!input || typeof input !== 'object') return undefined;
  const v = input as Record<string, unknown>;
  if (!REASONS.includes(v.reason as AnalysisGapReason)
    || !['index', 'flow', 'parse', 'unknown'].includes(v.phase as string)
    || !['site', 'check'].includes(v.extent as string) || !safeCount(v.observations) || v.observations === 0) return undefined;
  let location: AnalysisGap['location'];
  if (v.extent === 'site') {
    if (!(SITE_REASONS.has(v.reason as AnalysisGapReason) && v.phase === 'flow' || v.reason === 'parse_error' && v.phase === 'parse') || !v.location || typeof v.location !== 'object' || Array.isArray(v.location)) return undefined;
    const loc = v.location as Record<string, unknown>;
    if (typeof loc.path !== 'string' || loc.path.length > 4096 || loc.path.includes('\\')
      || loc.path.split('/').includes('..') || /^[A-Za-z][A-Za-z0-9+.-]*:/.test(loc.path)) return undefined;
    const path = safePath(loc.path);
    if (!path || path !== loc.path || !safeCount(loc.line) || loc.line < 1 || loc.line > 2147483647
      || !safeCount(loc.column) || loc.column < 1 || loc.column > 2147483647) return undefined;
    location = { path, line: loc.line, column: loc.column };
  } else if (v.location !== undefined) return undefined;
  if (v.reason === 'parse_error' && v.phase === 'parse' && v.extent === 'site'
    && (!safeCount(v.diagnosticCode) || v.diagnosticCode === 0)) return undefined;
  if (v.diagnosticCode !== undefined && (v.reason !== 'parse_error' || v.phase !== 'parse' || v.extent !== 'site'
    || !safeCount(v.diagnosticCode) || v.diagnosticCode === 0)) return undefined;
  const reason = v.reason as AnalysisGapReason;
  return { reason, phase: v.phase as AnalysisGap['phase'], extent: v.extent as AnalysisGap['extent'], observations: v.observations,
    ...(location ? { location } : {}), ...(v.diagnosticCode !== undefined ? { diagnosticCode: v.diagnosticCode as number } : {}), nextReview: nextGapReview(reason) };
}

/** Validates syntax/accounting only; it has no source inventory or runtime oracle. */
export function sanitiseAnalysisGaps(input: unknown, safePath: (value: string) => string | undefined): AnalysisGaps | undefined {
  if (input === undefined) return undefined;
  if (!input || typeof input !== 'object') return unknown([]);
  const v = input as Record<string, unknown>;
  const raw = Array.isArray(v.items) ? v.items : [];
  let valid = Array.isArray(v.items) && raw.length <= GAP_CHECK_LIMIT;
  const items: AnalysisGap[] = [];
  const byKey = new Map<string, AnalysisGap>();
  let total = 0;
  for (const row of raw.slice(0, GAP_CHECK_LIMIT)) {
    const item = gapItem(row, safePath);
    if (!item) { valid = false; continue; }
    const sum = add(total, item.observations);
    if (sum === undefined) { valid = false; continue; }
    total = sum;
    const key = keyOf(item); const prior = byKey.get(key);
    if (prior) prior.observations += item.observations;
    else { byKey.set(key, item); items.push(item); }
  }
  const gaps: AnalysisGaps = !valid || v.accounting !== 'exact' || !safeCount(v.eventsObserved) || !safeCount(v.eventsDropped)
    || add(total, v.eventsDropped) !== v.eventsObserved || v.truncated !== (v.eventsDropped > 0)
    ? unknown(items) : { accounting: 'exact', items, eventsObserved: v.eventsObserved, eventsDropped: v.eventsDropped, truncated: v.truncated };
  if (v.reasonSummary !== undefined) gaps.reasonSummary = sanitiseReasonSummary(v.reasonSummary, gaps);
  return gaps;
}

/** Moves already-accounted observations once; repeated sanitization is idempotent. */
export function capAnalysisGaps(gaps: AnalysisGaps, keep: number): AnalysisGaps {
  const n = Math.max(0, Math.min(gaps.items.length, keep));
  const items = gaps.items.slice(0, n).map(item => ({ ...item, ...(item.location ? { location: { ...item.location } } : {}) }));
  if (gaps.accounting === 'unknown') return unknown(items, gaps.reasonSummary !== undefined);
  const reasonSummary = gaps.reasonSummary ? { accounting: gaps.reasonSummary.accounting,
    rows: gaps.reasonSummary.rows.map(row => ({ ...row })) } : undefined;
  let dropped = gaps.eventsDropped!;
  for (const item of gaps.items.slice(n)) {
    const sum = add(dropped, item.observations);
    if (sum === undefined) return unknown(items, reasonSummary !== undefined);
    dropped = sum;
    if (reasonSummary?.accounting === 'exact') {
      const row = reasonSummary.rows.find(row => row.reason === item.reason);
      const moved = row && safeCount(row.eventsDropped) ? add(row.eventsDropped, item.observations) : undefined;
      if (moved === undefined) { reasonSummary.accounting = 'unknown'; reasonSummary.rows = []; }
      else row!.eventsDropped = moved;
    }
  }
  return { accounting: 'exact', items, eventsObserved: gaps.eventsObserved, eventsDropped: dropped, truncated: dropped > 0,
    ...(reasonSummary ? { reasonSummary } : {}) };
}
