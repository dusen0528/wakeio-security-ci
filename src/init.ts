import { COLLECTION_MAX_FILES, COLLECTION_MAX_BYTES, parseCollectionLimit } from './source/collection-budget.js';
import { resolveAnalysisBudget } from './source/analysis-budget.js';
import { access, constants, lstat, mkdir, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve } from "node:path";
import { inspectTree, parseTools } from "./doctor.js";

const CHECKOUT_SHA = "11d5960a326750d5838078e36cf38b85af677262";
const SETUP_NODE_SHA = "49933ea5288caeca8642d1e84afbd3f7d6820020";
const UPLOAD_ARTIFACT_SHA = "ea165f8d65b6e75b540449e92b4886f43607fa02";
const STABLE_SYSTEM_ALIASES = new Set(["/tmp", "/var"]);

interface InitOptions {
  requireCodeAnalysis?: boolean;
  sourceMaxFiles?: number;
  sourceMaxBytes?: number;
  analysisProfile?: 'default' | 'extended';
  source: string;
  workflow: string;
  out: string;
  tools: string[];
  help: boolean;
}

/**
 * Generate a reviewable local CI template without modifying an existing
 * file. The generated workflow invokes the installed npm CLI with
 * `npx --no-install`; it does not invent a registry package or unread config
 * file. Native scanner setup remains an explicit follow-up choice.
 */
export async function initMain(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  let options: InitOptions;
  try {
    options = parseInitArgs(argv);
  } catch (error) {
    process.stderr.write(`Error: ${error instanceof Error ? error.message : "invalid init arguments"}\n`);
    return 2;
  }
  if (options.help) {
    process.stdout.write(initUsage());
    return 0;
  }

  const root = resolve(options.source);
  let rootInfo;
  try { rootInfo = await lstat(root); } catch { rootInfo = undefined; }
  if (!rootInfo || rootInfo.isSymbolicLink() || !rootInfo.isDirectory()) {
    process.stderr.write("Error: init source must be an existing regular directory, not a symlink.\n");
    return 2;
  }
  const workflow = resolve(root, options.workflow);
  if (!isWithin(root, workflow)) {
    process.stderr.write("Error: init workflow must remain inside the source directory.\n");
    return 2;
  }
  if (hasControl(options.out)) {
    process.stderr.write("Error: init report directory contains unsupported control characters.\n");
    return 2;
  }

  // Inspect names and metadata only. This gives the generated comment an
  // honest Python applicability note without reading or executing source.
  const inventory = await inspectTree(root);
  let existing;
  try { existing = await lstat(workflow); } catch (error) { if ((error as { code?: string })?.code !== "ENOENT") return 2; }
  if (existing) {
    process.stderr.write(`Error: refusing to overwrite existing workflow: ${workflow}\n`);
    return 2;
  }
  try {
    await ensureParentDirectories(workflow);
    await writeFile(workflow, renderWorkflow({ ...options, pythonFiles: inventory.pythonFiles }), { encoding: "utf8", mode: 0o644, flag: "wx" });
  } catch {
    process.stderr.write("Error: init could not create the workflow without overwriting another file.\n");
    return 2;
  }
  process.stdout.write(`Created local CI template: ${workflow}\n`);
  process.stdout.write(`Static scope note: ${inventory.pythonFiles} Python file${inventory.pythonFiles === 1 ? "" : "s"} detected; Bandit remains an explicit optional setup.\n`);
  return 0;
}

export function parseInitArgs(argv: readonly string[]): InitOptions {
  const args = [...argv];
  if (args[0] === "init") args.shift();
  const options: InitOptions = { source: ".", workflow: join(".github", "workflows", "wakeio-security-ci.yml"), out: "wakeio-security-reports", tools: ["none"], help: false };
  const selected = new Set<string>();
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === '--require-code-analysis') {
      if (selected.has(argument)) throw new Error('--require-code-analysis may only be specified once');
      selected.add(argument); options.requireCodeAnalysis = true; continue;
    }
    const selector = argument.split('=')[0];
    if (['--source-max-files', '--source-max-bytes', '--analysis-profile'].includes(selector)) {
      if (selected.has(selector)) throw new Error(`${selector} may only be specified once`);
      selected.add(selector);
      const inline = argument.indexOf('=');
      const raw = inline >= 0 ? argument.slice(inline + 1) : args[++index];
      if (raw === undefined || raw === '') throw new Error(`${selector} requires a value`);
      if (selector === '--analysis-profile') options.analysisProfile = resolveAnalysisBudget(raw).requestedProfile;
      else {
        const maximum = selector === '--source-max-files' ? COLLECTION_MAX_FILES : COLLECTION_MAX_BYTES;
        let value: number;
        try { value = parseCollectionLimit(raw, maximum); }
        catch { throw new Error(`${selector} must be an integer from 1 to ${maximum} without signs, spaces or leading zeros`); }
        if (selector === '--source-max-files') options.sourceMaxFiles = value;
        else options.sourceMaxBytes = value;
      }
      continue;
    }
    if (argument === "--help" || argument === "-h") {
      options.help = true;
      continue;
    }
    if (["--source", "--root", "--workflow", "--out", "--tools"].includes(argument)) {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      index += 1;
      if (argument === "--source" || argument === "--root") options.source = value;
      else if (argument === "--workflow") options.workflow = value;
      else if (argument === "--out") options.out = value;
      else options.tools = parseTools(value);
      continue;
    }
    throw new Error(`unknown init option: ${argument}`);
  }
  if (isAbsolute(options.workflow)) throw new Error("--workflow must be relative to --source");
  if (hasControl(options.workflow) || hasControl(options.out)) throw new Error("--workflow and --out cannot contain control characters");
  return options;
}

export function initUsage(): string {
  return [
    "Usage: wakeio-security-ci init [--source DIR] [--workflow .github/workflows/wakeio-security-ci.yml] [--out DIR] [--tools none]",
    "",
    "       [--source-max-files N] [--source-max-bytes N] [--analysis-profile default|extended] [--require-code-analysis]",
    "",
    "Create a local CI workflow only when its destination does not exist; no file is overwritten.",
    "The template runs the installed CLI with npx --no-install and uses pinned helper-action commits.",
    "",
  ].join("\n");
}

export function renderWorkflow(options: { out: string; tools: string[]; pythonFiles: number; requireCodeAnalysis?: boolean; sourceMaxFiles?: number; sourceMaxBytes?: number; analysisProfile?: 'default' | 'extended' }): string {
  // Validate again because renderWorkflow is also exported for programmatic use.
  const files = options.sourceMaxFiles === undefined ? '' : ` --source-max-files ${parseCollectionLimit(String(options.sourceMaxFiles), COLLECTION_MAX_FILES)}`;
  const bytes = options.sourceMaxBytes === undefined ? '' : ` --source-max-bytes ${parseCollectionLimit(String(options.sourceMaxBytes), COLLECTION_MAX_BYTES)}`;
  const profile = options.analysisProfile === undefined ? '' : ` --analysis-profile ${resolveAnalysisBudget(options.analysisProfile).requestedProfile}`;
  if (options.requireCodeAnalysis !== undefined && typeof options.requireCodeAnalysis !== 'boolean') throw new Error('requireCodeAnalysis must be a boolean');
  const codePolicy = options.requireCodeAnalysis ? ' --require-code-analysis' : '';
  const toolValue = options.tools.length > 0 ? options.tools.join(",") : "none";
  const pythonNote = options.pythonFiles > 0
    ? `      # Static inventory detected ${options.pythonFiles} Python file${options.pythonFiles === 1 ? "" : "s"}; add a separately prepared Bandit executable before enabling --tools bandit.\n`
    : "      # No Python files were detected by the bounded static inventory; Bandit is not applicable.\n";
  return `name: wakeio-security-ci

on:
  push:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - name: Check out source
        uses: actions/checkout@${CHECKOUT_SHA}
        with:
          persist-credentials: false
      - name: Set up Node.js 22
        uses: actions/setup-node@${SETUP_NODE_SHA}
        with:
          node-version: '22'
      # Add wakeio-security-ci to this project's dependencies before using the template.
      # For an unpublished build, use a reviewed relative file:vendor/*.tgz dependency.
      - name: Install declared dependencies without lifecycle scripts
        run: npm ci --ignore-scripts --no-audit --fund=false
      - name: Run installed Wakeio CLI
${pythonNote}        run: >-
          npx --no-install wakeio-security-ci scan --source . --project-id "$GITHUB_REPOSITORY" --tools ${toolValue}${codePolicy}${files}${bytes}${profile} --out ${shellQuote(options.out)}
      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@${UPLOAD_ARTIFACT_SHA}
        with:
          name: wakeio-security-reports
          path: ${yamlQuote(options.out)}
          if-no-files-found: error
`;
}

function hasControl(value: string): boolean {
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 0x20 || code === 0x7f) return true;
  }
  return false;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function yamlQuote(value: string): string {
  return JSON.stringify(value);
}

function isWithin(root: string, candidate: string): boolean {
  const path = relative(root, candidate);
  return path === "" || (!path.startsWith("..") && !isAbsolute(path));
}

async function ensureParentDirectories(file: string): Promise<void> {
  const parent = resolve(file, "..");
  const root = resolve(parent, "/");
  const parts = parent.slice(root.length).split("/").filter(Boolean);
  let current = root;
  for (const part of parts) {
    current = join(current, part);
    let info;
    try { info = await lstat(current); } catch (error) {
      if ((error as { code?: string })?.code !== "ENOENT") throw error;
      await mkdir(current);
      info = await lstat(current);
    }
    if (info.isSymbolicLink()) {
      if (!STABLE_SYSTEM_ALIASES.has(current)) throw new Error("workflow parent contains a symbolic link");
      continue;
    }
    if (!info.isDirectory()) throw new Error("workflow parent is not a directory");
  }
}
