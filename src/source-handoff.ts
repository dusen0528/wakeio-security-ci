import { constants } from 'node:fs';
import { createHash, randomUUID } from 'node:crypto';
import { link, lstat, mkdir, open, realpath, unlink, writeFile } from 'node:fs/promises';
import { dirname, join, relative, resolve, sep } from 'node:path';
import type { AgentReport, FailOn, ScanReport, SourceSnapshotEvidence } from './contracts.js';
import { compareReports, comparisonExitCode, parseScanReport, type ComparisonState, type ReportComparison } from './compare.js';
import { evaluateGate, REPORT_TOOL_VERSION, RULESET_VERSION, toAgentReport } from './report.js';
import { collectSource } from './source/collector.js';
import { sameAnalysisBudget, sanitiseAnalysisBudget } from './source/analysis-budget.js';
import { sameCollectionBudget, sanitiseCollectionBudget, sanitiseCollectionEvidence } from './source/collection-budget.js';
import { sameSourceSnapshot, sanitiseSourceSnapshotEvidence, sourceSnapshotEvidence } from './source/snapshot-evidence.js';
import { safeRelativePath } from './report-path.js';

const HELP = `Usage:
  wakeio-security-ci handoff create --report DIR --source DIR --finding ID --check-index N --out NEW_DIR
  wakeio-security-ci handoff finish --handoff DIR --report AFTER_DIR --source DIR --out NEW_DIR

Data-only local review packet for built-in-only source reports. Recollects source as data.
Report, handoff and output directories must be outside the source; output must be new.
No scan, target execution, model, network request, patch, source writes or verified-fix claim.
Create: 0 packet produced (original scan gate retained), 2 refused/incomplete.
Finish: 0 completed comparable checked scope; 1 threshold findings; 2 unverified/incomplete.
Use the original scan command separately to produce the after report.
`;
const SHA = /^[a-f0-9]{64}$/;
const digest = (bytes: Buffer | string) => createHash('sha256').update(bytes).digest('hex');
const equal = (left: unknown, right: unknown) => JSON.stringify(left) === JSON.stringify(right);
const outside = (root: string, path: string) => path !== root && !path.startsWith(root.endsWith(sep) ? root : root + sep);
const fixedChecks = ['source.inventory', 'source.builtin-ast', 'source.framework'];
const verification = { vulnerabilityConfirmed: false, remediationVerified: false, securityControl: 'not_run', normalControl: 'not_run' } as const;
const limitations = [
  'A review packet and candidate disappearance are not vulnerability or fix verification.',
  'Snapshot binding matches collected UTF-8 strings, not raw file bytes or an atomic whole-tree snapshot.',
  'The aggregate is independent of an absolute checkout root; matching content does not authenticate the original root.',
  'Artifact digests and canonical projections check internal consistency, not signatures or author authenticity.',
  'Security and normal controls are not run. Reuse the original scan command separately; no command is inferred.',
  'Scan gate and packet delivery do not prove the final CI process status without its separate receipt.',
];

interface Options { operation: 'create' | 'finish'; report: string; source: string; out: string; handoff?: string; finding?: string; checkIndex?: number }
interface Pair { report: ScanReport; agent: AgentReport; reportBytes: Buffer; agentBytes: Buffer; reportSha256: string; agentReportSha256: string }
export interface SourceHandoffReceipt {
  version: 1;
  operation: 'create' | 'finish';
  status: 'ready' | 'rechecked';
  exitCode: 0 | 1 | 2;
  reason: 'review_packet_created' | 'checked_scope_rechecked' | 'threshold_findings' | 'comparison_unverified';
  input: { reportSha256: string; agentReportSha256: string };
  selected: { checkIndex: number; checkId: string; findingId: string; ruleId: string; comparisonKey?: string };
  scope: NonNullable<ScanReport['scope']>;
  sourceBinding: SourceSnapshotEvidence;
  originalScanGate: AgentReport['scanGate'];
  verification: typeof verification;
  limitations: string[];
  after?: { reportSha256: string; agentReportSha256: string; sourceBinding: SourceSnapshotEvidence; scanGate: AgentReport['scanGate'] };
  comparison?: ReportComparison;
  selectedState?: ComparisonState;
}

function fail(reason: string): never { throw new Error(reason); }
function parse(args: readonly string[]): Options {
  const operation = args[1];
  if (operation !== 'create' && operation !== 'finish') fail('invalid_arguments');
  const values = new Map<string, string>();
  const permitted = operation === 'create' ? ['--report', '--source', '--finding', '--check-index', '--out'] : ['--handoff', '--report', '--source', '--out'];
  for (let index = 2; index < args.length; index += 2) {
    const key = args[index], value = args[index + 1];
    if (!permitted.includes(key) || values.has(key) || !value || value.startsWith('--')) fail('invalid_arguments');
    values.set(key, value);
  }
  if (!permitted.every(key => values.has(key))) fail('invalid_arguments');
  const index = values.get('--check-index');
  if (index !== undefined && (!/^(?:0|[1-9][0-9]*)$/.test(index) || !Number.isSafeInteger(Number(index)) || Number(index) >= 1000)) fail('invalid_arguments');
  if (values.has('--finding') && !SHA.test(values.get('--finding')!)) fail('invalid_arguments');
  return { operation, report: resolve(values.get('--report')!), source: resolve(values.get('--source')!), out: resolve(values.get('--out')!),
    ...(operation === 'create' ? { finding: values.get('--finding')!, checkIndex: Number(index) } : { handoff: resolve(values.get('--handoff')!) }) };
}

/** Metadata checks reject redirected directories; macOS system /tmp and /var aliases remain usable. */
async function directory(path: string): Promise<string> {
  const target = resolve(path), root = resolve(target, '/');
  let current = root;
  for (const part of target.slice(root.length).split(sep).filter(Boolean)) {
    current = join(current, part);
    const info = await lstat(current);
    if (info.isSymbolicLink()) {
      if (current !== '/tmp' && current !== '/var') fail('unsafe_path');
    } else if (!info.isDirectory()) fail('unsafe_path');
  }
  return realpath(target);
}

async function boundedBytes(path: string, cap = 4 * 1024 * 1024): Promise<Buffer> {
  const handle = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const before = await handle.stat();
    if (!before.isFile() || before.nlink !== 1 || before.size > cap) fail('invalid_artifact');
    const bytes = Buffer.alloc(before.size + 1);
    let count = 0;
    while (count < bytes.length) {
      const next = await handle.read(bytes, count, bytes.length - count, count);
      if (!next.bytesRead) break;
      count += next.bytesRead;
    }
    const after = await handle.stat();
    if (count !== before.size || before.dev !== after.dev || before.ino !== after.ino || before.nlink !== after.nlink
      || before.size !== after.size || before.mtimeMs !== after.mtimeMs || before.ctimeMs !== after.ctimeMs) fail('invalid_artifact');
    return bytes.subarray(0, count);
  } finally { await handle.close(); }
}
function json(bytes: Buffer): unknown {
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)); }
  catch { return fail('invalid_artifact'); }
}
async function pair(path: string, names = ['report.json', 'agent-report.json']): Promise<Pair> {
  const reportBytes = await boundedBytes(join(path, names[0]));
  const agentBytes = await boundedBytes(join(path, names[1]));
  const rawReport = json(reportBytes), rawAgent = json(agentBytes) as AgentReport;
  if (!rawAgent || typeof rawAgent !== 'object' || rawAgent.schemaVersion !== '1.0.0'
    || !rawAgent.reportArtifact || rawAgent.reportArtifact.name !== 'report.json' || rawAgent.reportArtifact.algorithm !== 'sha256'
    || rawAgent.reportArtifact.digest !== digest(reportBytes) || !rawAgent.scanGate
    || !['critical', 'high', 'medium', 'low', 'info', 'none'].includes(rawAgent.scanGate.failOn)) fail('invalid_report_pair');
  const report = parseScanReport(rawReport);
  const agent = toAgentReport(report, rawAgent.scanGate.failOn as FailOn);
  if (!equal(agent, rawAgent)) fail('invalid_report_pair');
  return { report, agent, reportBytes, agentBytes, reportSha256: digest(reportBytes), agentReportSha256: digest(agentBytes) };
}

function supported(input: Pair): SourceSnapshotEvidence {
  const report = input.report;
  if (report.mode !== 'source' || report.toolVersion !== REPORT_TOOL_VERSION || report.scope?.ruleset !== RULESET_VERSION
    || ![fixedChecks.length, fixedChecks.length + 1].includes(report.checks.length)
    || !fixedChecks.every(id => report.checks.filter(check => check.id === id).length === 1)
    || report.checks.length === fixedChecks.length + 1 && report.checks.filter(check => check.id === 'source.code-coverage').length !== 1) fail('unsupported_scope');
  const inventory = report.checks.find(check => check.id === 'source.inventory')!;
  const ast = report.checks.find(check => check.id === 'source.builtin-ast')!;
  const collection = sanitiseCollectionBudget(inventory.collectionBudget);
  const evidence = sanitiseCollectionEvidence(inventory.collectionEvidence);
  const snapshot = sanitiseSourceSnapshotEvidence(inventory.sourceSnapshot);
  if (!collection || !sameCollectionBudget(collection, report.scope?.collectionBudget)
    || !sanitiseAnalysisBudget(ast.analysisBudget) || !sameAnalysisBudget(ast.analysisBudget, report.scope?.analysisBudget)
    || inventory.metrics?.requestedTools !== 'none' || inventory.metrics?.nativePreviewSelected !== false) fail('unsupported_scope');
  if (!snapshot || !snapshot.complete || snapshot.outputDirectoryExcluded || inventory.status !== 'completed'
    || !evidence || evidence.issues.some(issue => issue.code !== 'unsupported_file')
    || inventory.metrics?.complete !== true) fail('source_binding_unknown');
  return snapshot;
}
function selection(input: Pair, index: number, findingId: string): SourceHandoffReceipt['selected'] {
  const check = input.report.checks[index];
  const matches = check?.findings.filter(finding => finding.id === findingId) ?? [];
  if (!check || matches.length !== 1 || matches[0].kind !== 'candidate' || !matches[0].location.path
    || safeRelativePath(matches[0].location.path) !== matches[0].location.path) fail('invalid_finding');
  const finding = matches[0];
  if (finding.comparisonKey && check.findings.filter(other => other.comparisonKey === finding.comparisonKey).length !== 1) fail('ambiguous_finding');
  return { checkIndex: index, checkId: check.id, findingId, ruleId: finding.ruleId,
    ...(finding.comparisonKey ? { comparisonKey: finding.comparisonKey } : {}) };
}

async function currentSnapshot(source: string, input: Pair, checkCancelled: () => void,
  selected?: SourceHandoffReceipt['selected']): Promise<SourceSnapshotEvidence> {
  const expected = supported(input);
  const budget = input.report.scope!.collectionBudget!;
  checkCancelled();
  const snapshot = await collectSource({ root: source, maxFiles: budget.limits.maxFiles, maxBytes: budget.limits.maxBytes });
  checkCancelled();
  const observed = sourceSnapshotEvidence(snapshot);
  if (!observed.complete || !sameSourceSnapshot(expected, observed)) fail('source_drift_or_unknown');
  if (selected) {
    const finding = input.report.checks[selected.checkIndex].findings.find(item => item.id === selected.findingId)!;
    const paths = new Set(snapshot.files.map(file => file.path));
    const locations = [finding.location, ...(finding.staticFlow?.steps.map(step => step.location) ?? []),
      ...(finding.staticContext?.items.flatMap(item => item.target ? [item.location, item.target] : [item.location]) ?? [])];
    if (locations.some(location => !location.path || !paths.has(location.path))) fail('invalid_finding');
  }
  return observed;
}
function created(input: Pair, selected: SourceHandoffReceipt['selected'], sourceBinding: SourceSnapshotEvidence): SourceHandoffReceipt {
  return { version: 1, operation: 'create', status: 'ready', exitCode: 0, reason: 'review_packet_created',
    input: { reportSha256: input.reportSha256, agentReportSha256: input.agentReportSha256 }, selected,
    scope: input.report.scope!, sourceBinding, originalScanGate: input.agent.scanGate, verification: { ...verification }, limitations: [...limitations] };
}
function markdown(receipt: SourceHandoffReceipt, input: Pair): string {
  const finding = input.report.checks[receipt.selected.checkIndex].findings.find(item => item.id === receipt.selected.findingId)!;
  const inline = (value: string) => value.replace(/[\r\n\t]+/g, ' ').replace(/[\\`*_[\]{}()<>#+.!|\-]/g, '\\$&');
  // Navigation is escaped plain text, never rendered links/HTML or executable commands.
  return [ '# Local source review handoff', '',
    `Operation: ${receipt.operation}; packet status: ${receipt.status}; command exit: ${receipt.exitCode}.`,
    `Original scan gate: ${receipt.originalScanGate.outcome}; exit ${receipt.originalScanGate.exitCode}; threshold ${receipt.originalScanGate.failOn}.`,
    `Selected candidate: ${receipt.selected.findingId}; check index ${receipt.selected.checkIndex}; rule ${inline(receipt.selected.ruleId)}.`,
    `Local evidence: ${inline(finding.location.path!)}:${finding.location.line ?? 'unknown'}:${finding.location.column ?? 'unknown'}.`,
    `Before collected string snapshot: ${receipt.sourceBinding.digest}; matched the supplied source when create produced the review packet.`,
    ...(receipt.after ? [`After scan gate: ${receipt.after.scanGate.outcome}; exit ${receipt.after.scanGate.exitCode}.`,
      `After collected string snapshot: ${receipt.after.sourceBinding.digest}; matched the supplied source during this finish invocation.`,
      `Comparison: ${receipt.comparison!.comparable ? 'comparable declared scope' : 'unverified'}; selected state: ${receipt.selectedState}.`] : []),
    '', 'Review the local candidate evidence and its analysis gaps with a separately authorized coding tool. Preserve uncertainty.',
    'After a separately reviewed change, reuse the original CI scan command and options outside this command, then provide the after report to handoff finish.',
    'Security and normal controls: not_run. Vulnerability confirmed: false. Remediation verified: false.', '',
    ...receipt.limitations.map(item => `- ${item}`), '', ].join('\n');
}

async function publishReceipt(out: string, value: unknown, checkCancelled: () => void): Promise<void> {
  const temporary = join(out, `.handoff-${randomUUID()}.tmp`);
  try {
    checkCancelled();
    await writeFile(temporary, JSON.stringify(value, null, 2) + '\n', { mode: 0o600, flag: 'wx' });
    checkCancelled();
    await link(temporary, join(out, 'handoff.json'));
    checkCancelled();
  } finally { await unlink(temporary).catch(() => {}); }
}

/** Data-only supervisor; cooperative cancellation, not a hard process/filesystem sandbox. */
export async function handoffMain(args: readonly string[]): Promise<number> {
  if (args.length === 2 && args[1] === '--help'
    || args.length === 3 && ['create', 'finish'].includes(args[1]) && args[2] === '--help') { process.stdout.write(HELP); return 0; }
  let cancelled = false, out: string | undefined, operation: Options['operation'] | undefined;
  const cancel = () => { cancelled = true; };
  const checkCancelled = () => { if (cancelled) fail('cancelled'); };
  process.on('SIGINT', cancel); process.on('SIGTERM', cancel);
  const allowed = new Set(['invalid_arguments', 'unsafe_path', 'invalid_artifact', 'invalid_report_pair', 'unsupported_scope', 'source_binding_unknown',
    'invalid_finding', 'ambiguous_finding', 'source_drift_or_unknown', 'invalid_handoff', 'threshold_policy_changed', 'cancelled']);
  try {
    const options = parse(args); operation = options.operation;
    const source = await directory(options.source), reportDir = await directory(options.report), parent = await directory(dirname(options.out));
    const output = join(parent, relative(dirname(options.out), options.out));
    const handoffDir = options.handoff ? await directory(options.handoff) : undefined;
    if (![reportDir, output, ...(handoffDir ? [handoffDir] : [])].every(path => outside(source, path))) fail('unsafe_path');
    checkCancelled();
    await mkdir(output, { mode: 0o700 }); out = output;
    const input = await pair(handoffDir ?? reportDir);
    let receipt: SourceHandoffReceipt;
    const copies: Array<[string, Buffer]> = [];
    if (operation === 'create') {
      const selected = selection(input, options.checkIndex!, options.finding!);
      const sourceBinding = await currentSnapshot(source, input, checkCancelled, selected);
      receipt = created(input, selected, sourceBinding);
      copies.push(['report.json', input.reportBytes], ['agent-report.json', input.agentBytes]);
    } else {
      const previous = json(await boundedBytes(join(handoffDir!, 'handoff.json'))) as SourceHandoffReceipt;
      if (!previous || typeof previous !== 'object' || previous.operation !== 'create' || !previous.selected
        || !Number.isSafeInteger(previous.selected.checkIndex) || typeof previous.selected.findingId !== 'string') fail('invalid_handoff');
      const sourceBinding = supported(input);
      const selected = selection(input, previous.selected.checkIndex, previous.selected.findingId);
      const canonical = created(input, selected, sourceBinding);
      if (!equal(previous, canonical)) fail('invalid_handoff');
      const after = await pair(reportDir);
      if (after.agent.scanGate.failOn !== input.agent.scanGate.failOn) fail('threshold_policy_changed');
      const afterBinding = await currentSnapshot(source, after, checkCancelled);
      const comparison = compareReports(input.report, after.report);
      const code = Math.max(comparisonExitCode(comparison, input.agent.scanGate.failOn as FailOn), evaluateGate(after.report, input.agent.scanGate.failOn as FailOn).exitCode) as 0 | 1 | 2;
      const entry = comparison.entries.find(item => item.checkId === selected.checkId && (selected.comparisonKey
        ? item.finding.comparisonKey === selected.comparisonKey : item.finding.id === selected.findingId));
      receipt = { ...canonical, operation: 'finish', status: 'rechecked', exitCode: code,
        reason: code === 2 ? 'comparison_unverified' : code === 1 ? 'threshold_findings' : 'checked_scope_rechecked',
        after: { reportSha256: after.reportSha256, agentReportSha256: after.agentReportSha256, sourceBinding: afterBinding, scanGate: after.agent.scanGate },
        comparison, selectedState: entry?.state ?? 'unverified' };
      copies.push(['after-report.json', after.reportBytes], ['after-agent-report.json', after.agentBytes]);
    }
    for (const [name, bytes] of copies) { checkCancelled(); await writeFile(join(out, name), bytes, { mode: 0o600, flag: 'wx' }); }
    checkCancelled();
    await writeFile(join(out, 'handoff.md'), markdown(receipt, input), { mode: 0o600, flag: 'wx' });
    checkCancelled();
    await publishReceipt(out, receipt, checkCancelled);
    process.stdout.write(`Source handoff ${receipt.status}: exit ${receipt.exitCode}; original scan exit ${receipt.originalScanGate.exitCode}; verification not_run.\n`);
    return receipt.exitCode;
  } catch (error) {
    const reason = error instanceof Error && allowed.has(error.message) ? error.message : 'artifact_or_input_failed';
    if (out) {
      // A late failure must not leave a success-labelled Markdown sibling.
      await unlink(join(out, 'handoff.md')).catch(() => {});
      // Remove any final marker if cancellation raced its publication; publish only incomplete state.
      await unlink(join(out, 'handoff.json')).catch(() => {});
      await publishReceipt(out, { version: 1, operation, status: 'incomplete', exitCode: 2, reason, verification: { ...verification } }, () => {}).catch(() => {});
    }
    process.stdout.write(`Source handoff INCOMPLETE: ${reason}; exit 2; verification not_run.\n`);
    return 2;
  } finally { process.removeListener('SIGINT', cancel); process.removeListener('SIGTERM', cancel); }
}
