import type { CheckResult, CodeCoverage, CodeLanguage, CodeProvider, SourceOptions, ToolName } from '../contracts.js';
import { snapshotJsonData } from '../json-snapshot.js';
import { codeAnalyzer } from '../runtime/registry.js';
import type { SourceSnapshot } from './types.js';

export const CODE_COVERAGE_ID = 'source.code-coverage';
export const CODE_LANGUAGES: readonly CodeLanguage[] = ['javascript', 'typescript', 'python', 'c', 'cpp', 'csharp', 'go', 'java', 'kotlin', 'php', 'ruby', 'rust', 'shell', 'swift', 'vue'];
export const LEGACY_CODE_PROVIDERS_V1: readonly CodeProvider[] = Object.freeze([
  'builtin_ast', 'bandit', 'opengrep_native',
]);
export const CODE_PROVIDERS_V1: readonly CodeProvider[] = Object.freeze([...LEGACY_CODE_PROVIDERS_V1, 'semgrep']);
const LEGACY_PROVIDERS = LEGACY_CODE_PROVIDERS_V1, PROVIDERS = CODE_PROVIDERS_V1;
const EXTENSIONS: Record<string, CodeLanguage> = { '.js': 'javascript', '.jsx': 'javascript', '.mjs': 'javascript', '.cjs': 'javascript', '.ts': 'typescript', '.tsx': 'typescript', '.mts': 'typescript', '.cts': 'typescript', '.py': 'python', '.c': 'c', '.h': 'c', '.cc': 'cpp', '.cpp': 'cpp', '.hh': 'cpp', '.hpp': 'cpp', '.cs': 'csharp', '.go': 'go', '.java': 'java', '.kt': 'kotlin', '.php': 'php', '.rb': 'ruby', '.rs': 'rust', '.sh': 'shell', '.swift': 'swift', '.vue': 'vue' };
const count = (v: unknown): v is number => Number.isSafeInteger(v) && Number(v) >= 0 && Number(v) <= 10_000;
const exact = (v: unknown, keys: readonly string[]): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v) && Object.keys(v).length === keys.length && keys.every(k => Object.hasOwn(v, k));
const emptyCounts = () => ({ collected: null, eligible: null, completed: null, uncovered: null });
const supports = (p: CodeProvider, l: CodeLanguage) => codeAnalyzer(p).codeCoverage.languages.includes(l);

export function collectedCodeMetrics(snapshot: SourceSnapshot): Record<string, number> {
  const result: Record<string, number> = Object.fromEntries(CODE_LANGUAGES.map(language => [`codeFiles_${language}`, 0]));
  for (const file of snapshot.files.filter(f => f.category === 'code')) {
    const language = EXTENSIONS[file.path.toLowerCase().slice(file.path.lastIndexOf('.'))];
    if (language) result[`codeFiles_${language}`]++;
  }
  return result;
}

export function unknownCodeCoverage(required = false): CodeCoverage {
  return { version: 1, basis: 'collected_code_inputs', requireCodeAnalysis: required, collectionComplete: false, accounting: 'unknown', languages: [], totals: emptyCounts() };
}

/** No extra reads: classify only the collector's accepted code inputs. */
export function codeCoverageCheck(snapshot: SourceSnapshot | undefined, checks: readonly CheckResult[], options: Pick<SourceOptions, 'requireCodeAnalysis' | 'tools' | 'nativePreview'>): CheckResult {
  const required = options.requireCodeAnalysis === true;
  if (!snapshot) return coverageCheck(unknownCodeCoverage(required));
  const files = snapshot.files.filter(f => f.category === 'code');
  if (files.some(f => !EXTENSIONS[f.path.toLowerCase().slice(f.path.lastIndexOf('.'))])) return coverageCheck(unknownCodeCoverage(required));
  const selectionOptions = { root: snapshot.root, tools: options.tools, nativePreview: options.nativePreview };
  const selected = Object.fromEntries(
    PROVIDERS.map(p => [p, codeAnalyzer(p).selected(selectionOptions)]),
  ) as Record<CodeProvider, boolean>;
  const providers = selected.semgrep ? PROVIDERS : LEGACY_PROVIDERS;
  const inputSets = Object.fromEntries(PROVIDERS.map(p => [p, codeAnalyzer(p).codeCoverage.inputs(snapshot)]));
  const inputs = (p: CodeProvider) => inputSets[p];
  const statuses = Object.fromEntries(PROVIDERS.map(p => [p,
    checks.find(c => c.id === codeAnalyzer(p).checkId)?.status ?? 'unknown',
  ])) as Record<CodeProvider, CheckResult['status'] | 'unknown'>;
  const completed = (p: CodeProvider): boolean => {
    const analyzer = codeAnalyzer(p), check = checks.find(c => c.id === analyzer.checkId), n = inputs(p).length;
    return selected[p] && check?.status === 'completed' && n > 0 && analyzer.codeCoverage.complete(check, n);
  };
  const languages: CodeCoverage['languages'] = CODE_LANGUAGES.flatMap(language => {
    const collected = files.filter(f => EXTENSIONS[f.path.toLowerCase().slice(f.path.lastIndexOf('.'))] === language).length;
    if (!collected) return [];
    const perProvider = (provider: CodeProvider) => inputs(provider).filter(f => EXTENSIONS[f.path.toLowerCase().slice(f.path.lastIndexOf('.'))] === language);
    const providerRows = providers.map(provider => ({ provider, selected: selected[provider], status: selected[provider] ? statuses[provider] : 'not_selected' as const,
      eligible: selected[provider] ? perProvider(provider).length : 0, completed: selected[provider] && completed(provider) ? perProvider(provider).length : 0 }));
    const eligible = new Set(PROVIDERS.flatMap(p => selected[p] ? perProvider(p).map(f => f.path) : [])).size;
    const done = new Set(PROVIDERS.flatMap(p => selected[p] && completed(p) ? perProvider(p).map(f => f.path) : [])).size;
    return [{ language, collected, eligible, completed: done, uncovered: collected - done, providers: providerRows }];
  });
  const totals = { collected: files.length, eligible: 0, completed: 0, uncovered: 0 };
  for (const row of languages) { totals.eligible += row.eligible!; totals.completed += row.completed!; totals.uncovered += row.uncovered!; }
  return coverageCheck({ version: 1, basis: 'collected_code_inputs', requireCodeAnalysis: required, collectionComplete: snapshot.complete, accounting: 'exact', languages, totals });
}

function coverageCheck(codeCoverage: CodeCoverage): CheckResult {
  return { id: CODE_COVERAGE_ID, status: coverageIncomplete(codeCoverage) ? 'partial' : 'completed', findings: [], codeCoverage,
    notes: ['Code coverage counts describe collected code inputs only, not vulnerability completeness or whole-project safety.',
      'Eligible means selected provider input support, not submitted or executed. Completed requires a validated complete code-analysis result; partial providers contribute zero completed files.',
      'Secrets, advisory, configuration and framework checks do not establish code-analysis completion.'] };
}
export function coverageIncomplete(v: CodeCoverage): boolean {
  return v.accounting !== 'exact' || v.requireCodeAnalysis && (!v.collectionComplete || !v.totals.collected || v.totals.uncovered !== 0);
}

/** Strict canonical data, including arithmetic; unknown never acquires invented zero counts. */
export function parseCodeCoverage(input: unknown): CodeCoverage | undefined {
  let v: unknown; try { v = snapshotJsonData(input); } catch { return undefined; }
  if (!exact(v, ['version', 'basis', 'requireCodeAnalysis', 'collectionComplete', 'accounting', 'languages', 'totals']) || v.version !== 1 || v.basis !== 'collected_code_inputs' || typeof v.requireCodeAnalysis !== 'boolean' || typeof v.collectionComplete !== 'boolean' || !Array.isArray(v.languages) || v.languages.length > CODE_LANGUAGES.length || !exact(v.totals, ['collected', 'eligible', 'completed', 'uncovered'])) return undefined;
  if (v.accounting === 'unknown') return v.collectionComplete === false && v.languages.length === 0 && Object.values(v.totals).every(n => n === null) ? structuredClone(v) as unknown as CodeCoverage : undefined;
  if (v.accounting !== 'exact') return undefined;
  let previous = -1;
  let providerCount: number | undefined;
  const sums = { collected: 0, eligible: 0, completed: 0, uncovered: 0 };
  const providerIdentity = new Map<string, string>();
  for (const raw of v.languages) {
    if (!exact(raw, ['language', 'collected', 'eligible', 'completed', 'uncovered', 'providers']) || !CODE_LANGUAGES.includes(raw.language as CodeLanguage) || !Array.isArray(raw.providers) || ![LEGACY_PROVIDERS.length, PROVIDERS.length].includes(raw.providers.length)) return undefined;
    if (providerCount !== undefined && providerCount !== raw.providers.length) return undefined;
    providerCount = raw.providers.length;
    const order = CODE_LANGUAGES.indexOf(raw.language as CodeLanguage); if (order <= previous) return undefined; previous = order;
    if (!count(raw.collected) || raw.collected === 0 || !count(raw.eligible) || !count(raw.completed) || !count(raw.uncovered) || raw.completed > raw.eligible || raw.eligible > raw.collected || raw.uncovered !== raw.collected - raw.completed) return undefined;
    let eligible = 0, done = 0;
    for (let i = 0; i < raw.providers.length; i++) {
      const p = raw.providers[i];
      if (!exact(p, ['provider', 'selected', 'status', 'eligible', 'completed']) || p.provider !== PROVIDERS[i] || typeof p.selected !== 'boolean' || !count(p.eligible) || !count(p.completed) || p.completed > p.eligible || p.eligible > raw.collected) return undefined;
      if (!p.selected ? p.status !== 'not_selected' || p.eligible !== 0 || p.completed !== 0 : typeof p.status !== 'string' || !['completed', 'partial', 'error', 'not_applicable', 'skipped', 'unknown'].includes(p.status)) return undefined;
      if ((!supports(PROVIDERS[i], raw.language as CodeLanguage) || p.status === 'not_applicable') && (p.eligible !== 0 || p.completed !== 0) || p.status !== 'completed' && p.completed !== 0 || p.completed !== 0 && p.completed !== p.eligible) return undefined;
      const identity = JSON.stringify([p.selected, p.status]); if (providerIdentity.has(String(p.provider)) && providerIdentity.get(String(p.provider)) !== identity) return undefined; providerIdentity.set(String(p.provider), identity);
      eligible = Math.max(eligible, p.eligible); done = Math.max(done, p.completed);
    }
    if (eligible !== raw.eligible || done !== raw.completed) return undefined;
    for (const key of ['collected', 'eligible', 'completed', 'uncovered'] as const) {
      const n = raw[key];
      if (!count(n)) return undefined;
      sums[key] += n;
    }
  }
  const totals = v.totals;
  if (Object.entries(sums).some(([key, n]) => !count(n) || totals[key] !== n)) return undefined;
  return structuredClone(v) as unknown as CodeCoverage;
}

/** Consistency only; external reports are not authenticated execution receipts. */
export function codeCoverageConsistent(v: CodeCoverage, checks: readonly CheckResult[]): boolean {
  if (v.accounting === 'unknown') return true;
  const inventory = checks.filter(c => c.id === 'source.inventory');
  if (inventory.length !== 1 || !count(inventory[0].metrics?.filesSelected) || inventory[0].metrics?.codeFilesSelected !== v.totals.collected || inventory[0].metrics?.complete !== v.collectionComplete || Number(inventory[0].metrics?.filesSelected) < v.totals.collected!) return false;
  for (const language of CODE_LANGUAGES) {
    if (inventory[0].metrics?.[`codeFiles_${language}`] !== (v.languages.find(row => row.language === language)?.collected ?? 0)) return false;
  }
  const requested = inventory[0].metrics?.requestedTools;
  const nativeSelected = inventory[0].metrics?.nativePreviewSelected;
  if (typeof requested !== 'string' || typeof nativeSelected !== 'boolean') return false;
  if (requested.split(',').includes('semgrep') && v.languages.some(row => !row.providers.some(p => p.provider === 'semgrep'))) return false;
  for (const provider of PROVIDERS) {
    const rows = v.languages.flatMap(row => row.providers.filter(p => p.provider === provider));
    if (!rows.length) continue;
    const analyzer = codeAnalyzer(provider);
    const identity = rows[0], expectedSelected = analyzer.selected({ root: '',
      tools: requested.split(',') as ToolName[], nativePreview: nativeSelected ? { executable: '' } : undefined });
    if (identity.selected !== expectedSelected) return false;
    const actual = checks.filter(c => c.id === analyzer.checkId);
    if (identity.selected && (actual.length !== 1 || actual[0].status !== identity.status) || !identity.selected && actual.length !== 0) return false;
    const eligible = rows.reduce((sum, row) => sum + row.eligible!, 0), done = rows.reduce((sum, row) => sum + row.completed!, 0);
    const inputCount = actual[0] && analyzer.codeCoverage.inputCount(actual[0]);
    if (identity.selected && inputCount !== undefined && (!count(inputCount) || inputCount !== eligible)) return false;
    if (done > 0) {
      if (!actual[0] || !analyzer.codeCoverage.complete(actual[0], eligible)) return false;
      if (done !== eligible) return false;
    }
  }
  return true;
}
