import { lstat, mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, isAbsolute, join, relative, resolve } from 'node:path';
import type { CheckResult, Finding, Severity } from './contracts.js';
import { runProcess } from './source/process.js';
import { stageSnapshot, type StagedSnapshot } from './source/collector.js';
import type { CollectedFile, ParsedToolResult, SourceSnapshot } from './source/types.js';
import { inspectRequirementsFile } from './source/requirements.js';

const MANIFESTS = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'yarn.lock', 'pnpm-lock.yaml', 'go.mod', 'go.sum', 'Cargo.lock', 'Gemfile.lock', 'poetry.lock', 'Pipfile.lock', 'uv.lock', 'requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt', 'packages.lock.json', 'composer.lock']);
const SEVERITIES: Record<string, Severity> = { UNKNOWN: 'info', LOW: 'low', MEDIUM: 'medium', HIGH: 'high', CRITICAL: 'critical' };

export function isTrivyVulnerabilityManifest(path: string): boolean { return MANIFESTS.has(basename(path)); }

export function trivyVulnerabilityFiles(snapshot: SourceSnapshot): CollectedFile[] {
  return snapshot.files.filter(file => !file.sensitive && file.category === 'dependency' && isTrivyVulnerabilityManifest(file.path));
}

export interface TrivyVulnerabilityOptions {
  toolPath: string;
  timeoutMs: number;
  signal?: AbortSignal;
  snapshot?: SourceSnapshot;
  stageDir?: string;
  /** A local Docker/OCI image tar archive; no registry pull or image execution. */
  imageArchive?: string;
  cacheDir?: string;
  offline?: boolean;
}

interface ParseOptions { stageDir?: string; allowedPaths?: string[]; image?: boolean }
function object(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid record');
  return value as Record<string, unknown>;
}
function identifier(value: unknown, max = 512): string {
  if (typeof value !== 'string' || value.length < 1 || value.length > max || !/^[A-Za-z0-9@][A-Za-z0-9_@./+!~:,*()=<> -]*$/.test(value)) throw new Error('invalid identifier');
  return value;
}
function sourcePath(value: unknown, options: ParseOptions): string {
  if (typeof value !== 'string' || !options.stageDir) throw new Error('invalid path');
  const path = relative(resolve(options.stageDir), resolve(options.stageDir, value)).replaceAll('\\', '/');
  if (isAbsolute(path) || path.startsWith('../') || !(options.allowedPaths ?? []).includes(path)) throw new Error('unmapped path');
  return path;
}

export function parseTrivyVulnerabilityOutput(text: string, options: ParseOptions): ParsedToolResult {
  if (Buffer.byteLength(text) > 8 * 1024 * 1024) throw new Error('output limit');
  const root = object(JSON.parse(text));
  if (root.SchemaVersion !== 2 || !Array.isArray(root.Results)) throw new Error('invalid report envelope');
  if (options.image ? root.ArtifactType !== 'container_image' : root.ArtifactType !== 'filesystem') throw new Error('wrong artifact type');
  const findings = new Map<string, Finding>(), scanned = new Set<string>();
  let packages = 0, resultCount = 0;
  for (const raw of root.Results) {
    const result = object(raw);
    if (result.Class !== 'lang-pkgs' && result.Class !== 'os-pkgs') throw new Error('unexpected result class');
    if (!options.image && result.Class !== 'lang-pkgs') throw new Error('unexpected OS input');
    if (typeof result.Type !== 'string' || !/^[a-z0-9-]{1,40}$/.test(result.Type)) throw new Error('invalid package type');
    const path = options.image ? `image/${result.Class}/${result.Type}` : sourcePath(result.Target, options);
    scanned.add(path); resultCount++;
    if (!Array.isArray(result.Packages)) throw new Error('missing package inventory');
    packages += result.Packages.length;
    for (const rawPackage of result.Packages) {
      const pkg = object(rawPackage); identifier(pkg.Name);
      // Trivy includes the unversioned root Go module in its package graph.
      if (pkg.Version !== undefined || pkg.Relationship !== 'root') identifier(pkg.Version);
    }
    if (result.Vulnerabilities != null && !Array.isArray(result.Vulnerabilities)) throw new Error('invalid vulnerability list');
    for (const rawVuln of (result.Vulnerabilities ?? []) as unknown[]) {
      const vuln = object(rawVuln), id = identifier(vuln.VulnerabilityID, 128), name = identifier(vuln.PkgName), installed = identifier(vuln.InstalledVersion);
      if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{1,127}$/.test(id) || typeof vuln.Severity !== 'string' || !Object.hasOwn(SEVERITIES, vuln.Severity)) throw new Error('invalid vulnerability');
      const fixed = vuln.FixedVersion ? identifier(vuln.FixedVersion) : undefined;
      if (!result.Packages.some(rawPackage => { const pkg = object(rawPackage); return pkg.Name === name && pkg.Version === installed; })) throw new Error('unbound package');
      const key = `${id}:${path}:${name}:${installed}`;
      const references: string[] = [];
      if (/^CVE-\d{4}-\d{4,}$/.test(id)) references.push(`https://nvd.nist.gov/vuln/detail/${id}`);
      else if (/^GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}$/.test(id)) references.push(`https://github.com/advisories/${id}`);
      findings.set(key, {
        ruleId: `trivy-vuln:${id}`, title: `${id} in ${name}`,
        description: `${name} ${installed} matches a known ${result.Class === 'os-pkgs' ? 'OS' : 'application'} package advisory. Package presence does not establish runtime reachability or exploitability.${vuln.Severity === 'UNKNOWN' ? ' The advisory has no severity rating; info is used rather than inferring a score.' : ''}`,
        severity: SEVERITIES[vuln.Severity]!, confidence: 'high', kind: 'advisory', location: { path },
        remediation: fixed ? `Upgrade ${name} to an unaffected version listed by the advisory (reported fixed versions: ${fixed}), rebuild the ${options.image ? 'image' : 'dependency lockfile'}, and rerun the scan.` : `No fixed version was reported for ${name}. Review the advisory, update the base image/dependency when a fix becomes available, or remove the affected package.`,
        ...(references.length ? { references } : {}),
      });
    }
  }
  // A valid empty result does not prove every requested manifest was supported.
  const unreported = options.image ? 0 : (options.allowedPaths ?? []).filter(path => !scanned.has(path) && !(basename(path) === 'go.sum' && scanned.has(path.replace(/go\.sum$/, 'go.mod')))).length;
  return { findings: [...findings.values()], status: unreported > 0 || resultCount === 0 || packages === 0 ? 'partial' : 'completed',
    notes: [`Trivy inspected ${packages} package records in ${resultCount} inventories. Findings identify affected package versions, not reachable application flaws.`,
      ...(unreported ? [`${unreported} selected dependency files did not produce an inventory; package coverage is incomplete.`] : []),
      ...(resultCount === 0 || packages === 0 ? ['No package inventory was reported; an empty result is not accepted as a clean vulnerability scan.'] : []),
      ...(options.image ? ['Image locations are synthetic inventory paths, not host source files. Only the supplied archive was inspected; the image was not run.'] : [])],
    metrics: { inventories: resultCount, packages, findingCount: findings.size, unreportedInputs: unreported } };
}

export async function runTrivyVulnerabilities(options: TrivyVulnerabilityOptions): Promise<CheckResult> {
  const image = options.imageArchive !== undefined, id = image ? 'image.trivy' : 'source.trivy-vuln';
  const check = (status: CheckResult['status'], note: string): CheckResult => ({ id, status, findings: [], notes: [note] });
  const files = options.snapshot ? trivyVulnerabilityFiles(options.snapshot) : [];
  const unresolvedRequirements = files.filter(file => /^requirements(?:-(?:dev|prod))?\.txt$/.test(basename(file.path)) && !inspectRequirementsFile(file.text).pinned).length;
  if (image && (options.snapshot || options.stageDir)) return check('error', 'Choose exactly one Trivy target: a staged source snapshot or a local image archive.');
  if (!image && (!options.snapshot || !options.stageDir)) return check('error', 'Trivy filesystem vulnerability scanning requires a staged source snapshot.');
  if (!image && files.length === 0) return check('not_applicable', 'No supported dependency inventory was collected for Trivy vulnerability scanning.');
  if (!options.toolPath) return check('partial', 'Trivy executable was not found; the selected package/image vulnerability scan was not performed.');
  let privateRoot: string | undefined, staged: StagedSnapshot | undefined;
  try {
    if (image) {
      const stat = await lstat(options.imageArchive!);
      if (!stat.isFile() || stat.isSymbolicLink()) return check('error', 'The image target must be a regular local Docker/OCI tar archive.');
    }
    if (!image) staged = await stageSnapshot({ ...options.snapshot!, files });
    privateRoot = await mkdtemp(join(tmpdir(), 'wakeio-trivy-vuln-'));
    const home = join(privateRoot, 'home'), modules = join(privateRoot, 'modules'), cache = options.cacheDir ? resolve(options.cacheDir) : join(privateRoot, 'cache');
    await Promise.all([home, modules, cache].map(path => mkdir(path, { recursive: true, mode: 0o700 })));
    const config = join(privateRoot, 'trivy.yaml'), ignore = join(privateRoot, 'empty.ignore');
    await writeFile(config, '{}\n', { mode: 0o600 });
    await writeFile(ignore, '', { mode: 0o600 });
    const args = [image ? 'image' : 'fs', '--quiet', '--disable-telemetry', '--skip-version-check', '--format', 'json', '--exit-code', '0', '--scanners', 'vuln', '--list-all-pkgs', '--pkg-types', image ? 'os,library' : 'library', '--config', config, '--ignorefile', ignore, '--cache-dir', cache, '--module-dir', modules, '--offline-scan', ...(!image ? ['--file-patterns', 'pip:(^|/)requirements-(dev|prod)\\.txt$'] : []), ...(options.offline ? ['--skip-db-update', '--skip-java-db-update'] : []), ...(image ? ['--input', resolve(options.imageArchive!)] : [staged!.dir])];
    const result = await runProcess(options.toolPath, args, { cwd: image ? privateRoot : staged!.dir, timeoutMs: options.timeoutMs, home, signal: options.signal });
    if (result.cancelled || result.spawnError || result.timedOut || result.outputLimitExceeded || result.signal || result.exitCode !== 0) return check('error', 'Trivy vulnerability scanning did not complete. Check the prepared database/cache, archive format, and timeout; no clean result is inferred from missing output.');
    const parsed = parseTrivyVulnerabilityOutput(result.stdout, { image, stageDir: staged?.dir, allowedPaths: files.map(file => file.path) });
    const incomplete = !image && options.snapshot?.complete === false;
    return { id, status: incomplete || unresolvedRequirements ? 'partial' : parsed.status ?? 'completed', findings: parsed.findings,
      notes: [...parsed.notes, ...(incomplete ? ['The collected snapshot was incomplete; dependency coverage is incomplete.'] : []),
        ...(unresolvedRequirements ? ['Python requirements contain an unresolved range, include, URL or option; only inventoried versions were checked and dependency coverage is incomplete.'] : [])],
      metrics: { ...parsed.metrics, unresolvedRequirements } };
  } catch { return check('error', 'Trivy returned invalid vulnerability data or its target/cache could not be read.'); }
  finally { await staged?.cleanup(); if (privateRoot) await rm(privateRoot, { recursive: true, force: true }); }
}
