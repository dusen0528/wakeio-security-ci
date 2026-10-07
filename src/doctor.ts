import { access, constants, lstat, readdir, stat } from "node:fs/promises";
import { join, resolve } from "node:path";
import type { Dirent } from "node:fs";
import { findExecutable as findScannerExecutable } from "./source/process.js";

const DEFAULT_TOOLS = ["gitleaks", "osv", "trivy"] as const;
const TOOL_NAMES = new Set(["gitleaks", "osv", "trivy", "bandit"]);
const SKIPPED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  ".venv",
  ".venv-schemathesis",
  ".hypothesis",
  "venv",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".intent-review",
  "vendor",
  "build",
  "dist",
  "out",
  "coverage",
  "artifacts",
  "realreports",
  "results",
  "wakeio-security-reports",
  ".wakeio-security-ci",
]);
const MAX_INVENTORY_FILES = 20_000;
const MAX_INVENTORY_DIRECTORIES = 5_000;

interface Inventory {
  files: number;
  bytes: number;
  pythonFiles: number;
  dependencyManifests: number;
  configFiles: number;
  truncated: boolean;
}

interface DoctorOptions {
  source: string;
  tools: string[];
  json: boolean;
  strict: boolean;
  help: boolean;
  /** Also report readiness of the opt-in active DAST engines (metadata only). */
  dast: boolean;
  nuclei?: string;
  nucleiTemplates?: string;
  schemathesisPython?: string;
}

export interface DoctorDastStatus {
  nuclei: { availability: "available" | "missing"; path?: string; pinnedVersion: string; install: string };
  nucleiTemplates: { availability: "available" | "missing" | "not_configured"; scopes: string[]; checksumFile: boolean; note: string };
  schemathesisPython: { availability: "available" | "missing"; path?: string; requirements: string };
  consent: string;
}

export interface DoctorToolStatus {
  name: string;
  applicability: "applicable" | "not_applicable" | "unknown";
  availability: "available" | "missing" | "not_applicable";
  path?: string;
}

/**
 * Read-only environment and scope inspection for a planned scan.
 *
 * This module deliberately uses directory metadata only. It does not open
 * source files, invoke package managers or target scripts, start scanners, or
 * make network requests.
 */
export async function doctorMain(argv: readonly string[] = process.argv.slice(2)): Promise<number> {
  let options: DoctorOptions;
  try {
    options = parseDoctorArgs(argv);
  } catch (error) {
    process.stderr.write(`Error: ${error instanceof Error ? error.message : "invalid doctor arguments"}\n`);
    return 2;
  }
  if (options.help) {
    process.stdout.write(doctorUsage());
    return 0;
  }

  const source = resolve(options.source);
  let info;
  try {
    info = await lstat(source);
  } catch {
    process.stderr.write("Error: doctor source directory could not be inspected.\n");
    return 2;
  }
  if (info.isSymbolicLink() || !info.isDirectory()) {
    process.stderr.write("Error: doctor source must be a regular directory, not a symlink.\n");
    return 2;
  }

  const inventory = await inspectTree(source);
  const toolStatuses = await inspectTools(options.tools, inventory);
  const expectedTransfers = toolStatuses
    .filter((tool) => tool.availability === "missing" && tool.applicability !== "not_applicable")
    .map((tool) => tool.name === "bandit"
      ? "separately prepared trusted Bandit executable or Python environment (the native archive installer does not provide Bandit)"
      : `pinned ${tool.name} release archive (installer verifies the upstream SHA-256 before extraction)`);
  const runtimeNetwork: string[] = [];
  if (options.tools.includes("osv") && inventory.dependencyManifests > 0) {
    runtimeNetwork.push("OSV package/version and vulnerability lookups may use the public service unless an explicit prepared offline DB is supplied");
  }
  if (options.tools.includes("trivy") && inventory.configFiles > 0) {
    runtimeNetwork.push("Trivy policy/DB traffic may be scanner-managed and is not verified by this Action");
  }
  const dast = options.dast ? await inspectDast(options) : undefined;
  const result = {
    schemaVersion: "1.0.0",
    source: source,
    execution: { targetCode: "none", network: "none", packageManager: "none" },
    inventory,
    tools: toolStatuses,
    expectedTransfers,
    runtimeNetwork,
    databaseCaches: { osv: "unknown", trivy: "unknown" },
    nextCommand: nextCommand(source, options.tools),
    ...(dast ? { activeDast: dast } : {}),
  };

  if (options.json) {
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  } else {
    process.stdout.write(renderDoctorText(result));
  }

  if (options.strict && (inventory.truncated || toolStatuses.some((tool) => tool.availability === "missing" && tool.applicability !== "not_applicable"))) return 2;
  if (options.strict && dast && (dast.nuclei.availability !== "available" || dast.nucleiTemplates.availability !== "available" || dast.schemathesisPython.availability !== "available")) return 2;
  return 0;
}

export function parseDoctorArgs(argv: readonly string[]): DoctorOptions {
  const args = [...argv];
  if (args[0] === "doctor") args.shift();
  const options: DoctorOptions = { source: ".", tools: [...DEFAULT_TOOLS], json: false, strict: false, help: false, dast: false };
  for (let index = 0; index < args.length; index += 1) {
    const argument = args[index];
    if (argument === "--help" || argument === "-h") {
      options.help = true;
      continue;
    }
    if (argument === "--json") {
      options.json = true;
      continue;
    }
    if (argument === "--strict") {
      options.strict = true;
      continue;
    }
    if (argument === "--dast") {
      options.dast = true;
      continue;
    }
    if (argument === "--nuclei" || argument === "--nuclei-templates" || argument === "--schemathesis-python") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      index += 1;
      if (argument === "--nuclei") options.nuclei = value;
      else if (argument === "--nuclei-templates") options.nucleiTemplates = value;
      else options.schemathesisPython = value;
      continue;
    }
    if (argument === "--source" || argument === "--root" || argument === "--tools") {
      const value = args[index + 1];
      if (!value || value.startsWith("--")) throw new Error(`${argument} requires a value`);
      index += 1;
      if (argument === "--source" || argument === "--root") options.source = value;
      else options.tools = parseTools(value);
      continue;
    }
    throw new Error(`unknown doctor option: ${argument}`);
  }
  if (!options.dast && (options.nuclei || options.nucleiTemplates || options.schemathesisPython)) throw new Error("--nuclei, --nuclei-templates and --schemathesis-python require --dast");
  return options;
}

/** Executable/directory metadata only: nothing is run and no template is parsed. */
async function inspectDast(options: DoctorOptions): Promise<DoctorDastStatus> {
  const nuclei = await findExecutable(options.nuclei ?? "nuclei");
  // Virtualenv interpreters are symlinks by design, so follow the link for this check only.
  const pythonPath = resolve(options.schemathesisPython ?? process.env.WAKEIO_SCHEMATHESIS_PYTHON ?? join(process.cwd(), ".venv-schemathesis/bin/python"));
  const python = await stat(pythonPath).then(async (stats) => stats.isFile() && await access(pythonPath, constants.X_OK).then(() => true, () => false)).catch(() => false) ? pythonPath : undefined;
  let templates: DoctorDastStatus["nucleiTemplates"] = { availability: "not_configured", scopes: [], checksumFile: false,
    note: "Prepare templates once (for example `nuclei -ut -ud DIR`) and pass --nuclei-templates; scans never download templates." };
  if (options.nucleiTemplates) {
    const root = resolve(options.nucleiTemplates);
    const scopes: string[] = [];
    for (const [name, path] of [["misconfiguration", "http/misconfiguration"], ["exposures", "http/exposures"]] as const) {
      const stats = await lstat(join(root, ...path.split("/"))).catch(() => undefined);
      if (stats?.isDirectory() && !stats.isSymbolicLink()) scopes.push(name);
    }
    const checksum = await lstat(join(root, "templates-checksum.txt")).then((stats) => stats.isFile()).catch(() => false);
    templates = { availability: scopes.length > 0 ? "available" : "missing", scopes, checksumFile: checksum,
      note: checksum ? "templates-checksum.txt digest is recorded as provenance at scan time." : "templates-checksum.txt is missing; template provenance will be unknown." };
  }
  return {
    nuclei: { availability: nuclei ? "available" : "missing", ...(nuclei ? { path: nuclei } : {}), pinnedVersion: "3.11.1",
      install: "node scripts/install-tools.mjs --tools nuclei (verifies the pinned upstream SHA-256)" },
    nucleiTemplates: templates,
    schemathesisPython: { availability: python ? "available" : "missing", ...(python ? { path: python } : {}),
      requirements: "Python 3.12 with workers/schemathesis/requirements.lock.txt (package versions are checked when a scan starts the worker)" },
    consent: "Active DAST also requires --active-consent at scan time; doctor never sends requests.",
  };
}

export function parseTools(value: string): string[] {
  if (value.trim().toLowerCase() === "none") return [];
  const tools = value.split(",").map((tool) => tool.trim().toLowerCase()).filter(Boolean);
  if (tools.length === 0 || tools.includes("none") || tools.some((tool) => !TOOL_NAMES.has(tool)) || new Set(tools).size !== tools.length) {
    throw new Error("--tools must be a comma-separated list of gitleaks, osv, trivy, bandit, or none");
  }
  return tools;
}

export function doctorUsage(): string {
  return [
    "Usage: wakeio-security-ci doctor [--source DIR] [--tools gitleaks,osv,trivy,bandit|none] [--json] [--strict]",
    "                              [--dast [--nuclei PATH] [--nuclei-templates DIR] [--schemathesis-python PATH]]",
    "",
    "Read-only inventory: no target code, package scripts, scanner, or network request is executed.",
    "",
  ].join("\n");
}

export async function inspectTree(source: string): Promise<Inventory> {
  const inventory: Inventory = { files: 0, bytes: 0, pythonFiles: 0, dependencyManifests: 0, configFiles: 0, truncated: false };
  let directories = 0;
  const visit = async (directory: string): Promise<void> => {
    directories += 1;
    if (directories > MAX_INVENTORY_DIRECTORIES) {
      inventory.truncated = true;
      return;
    }
    let entries: Dirent[];
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch {
      inventory.truncated = true;
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      if (inventory.files >= MAX_INVENTORY_FILES) {
        inventory.truncated = true;
        return;
      }
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) {
        if (SKIPPED_DIRECTORIES.has(entry.name)) continue;
        await visit(join(directory, entry.name));
        if (inventory.truncated) return;
        continue;
      }
      if (!entry.isFile()) continue;
      const path = join(directory, entry.name);
      let stats;
      try { stats = await lstat(path); } catch { inventory.truncated = true; return; }
      inventory.files += 1;
      inventory.bytes += stats.size;
      const lower = entry.name.toLowerCase();
      if (lower.endsWith(".py")) inventory.pythonFiles += 1;
      if (new Set([
        "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
        "pyproject.toml", "requirements.txt", "poetry.lock", "uv.lock", "pipfile", "pipfile.lock", "cargo.toml", "cargo.lock",
        "go.mod", "go.sum", "gemfile", "gemfile.lock", "composer.json", "composer.lock",
      ]).has(lower)) inventory.dependencyManifests += 1;
      if (lower === "dockerfile" || lower.endsWith(".dockerfile") || /\.(?:ya?ml|tf|tfvars|hcl)(?:\.json)?$/i.test(lower)) inventory.configFiles += 1;
    }
  };
  await visit(source);
  return inventory;
}

async function inspectTools(selected: string[], inventory: Inventory): Promise<DoctorToolStatus[]> {
  const result: DoctorToolStatus[] = [];
  for (const name of selected) {
    if (name === "bandit" && inventory.pythonFiles === 0) {
      result.push({ name, applicability: "not_applicable", availability: "not_applicable" });
      continue;
    }
    const path = await findExecutable(name === "osv" ? "osv-scanner" : name);
    const applicability = name === "gitleaks"
      ? inventory.files > 0 ? "applicable" : "not_applicable"
      : name === "osv"
        ? inventory.dependencyManifests > 0 ? "applicable" : "unknown"
        : name === "trivy"
          ? inventory.configFiles > 0 ? "applicable" : "unknown"
          : "applicable";
    result.push({ name, applicability, availability: path ? "available" : "missing", ...(path ? { path } : {}) });
  }
  return result;
}

async function findExecutable(command: string): Promise<string | undefined> {
  // Reuse the scanner's metadata-only executable resolution so doctor and a
  // later scan have the same PATH and regular-file interpretation.
  return findScannerExecutable(command);
}

function nextCommand(source: string, tools: string[]): string {
  return `npx --no-install wakeio-security-ci scan --source ${shellQuote(source)} --tools ${shellQuote(tools.length > 0 ? tools.join(",") : "none")} --out wakeio-security-reports`;
}

function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

function renderDoctorText(result: { source: string; inventory: Inventory; tools: DoctorToolStatus[]; expectedTransfers: string[]; runtimeNetwork: string[]; databaseCaches: { osv: string; trivy: string }; nextCommand: string; activeDast?: DoctorDastStatus }): string {
  const dast = result.activeDast;
  const lines = [
    "Wakeio doctor (read-only)",
    `Source: ${result.source}`,
    `Inventory: ${result.inventory.files} files, ${result.inventory.bytes} bytes; Python ${result.inventory.pythonFiles}; dependency manifests ${result.inventory.dependencyManifests}; config files ${result.inventory.configFiles}${result.inventory.truncated ? "; truncated" : ""}`,
    "Target execution: none; network: none; package manager: none",
    ...result.tools.map((tool) => `Tool ${tool.name}: ${tool.availability} (${tool.applicability})${tool.path ? ` at ${tool.path}` : ""}`),
    `Expected transfers: ${result.expectedTransfers.length > 0 ? result.expectedTransfers.join("; ") : "none"}`,
    `Runtime network expectations: ${result.runtimeNetwork.length > 0 ? result.runtimeNetwork.join("; ") : "none"}`,
    `OSV database cache: ${result.databaseCaches.osv}; Trivy database cache: ${result.databaseCaches.trivy}`,
    `Next command: ${result.nextCommand}`,
    ...(dast ? [
      `Active DAST nuclei ${dast.nuclei.pinnedVersion}: ${dast.nuclei.availability}${dast.nuclei.path ? ` at ${dast.nuclei.path}` : ` (install: ${dast.nuclei.install})`}`,
      `Active DAST nuclei templates: ${dast.nucleiTemplates.availability}${dast.nucleiTemplates.scopes.length ? ` (${dast.nucleiTemplates.scopes.join(", ")})` : ""}; ${dast.nucleiTemplates.note}`,
      `Active DAST Schemathesis Python: ${dast.schemathesisPython.availability}${dast.schemathesisPython.path ? ` at ${dast.schemathesisPython.path}` : ""}; ${dast.schemathesisPython.requirements}`,
      dast.consent,
    ] : []),
    "",
  ];
  return lines.join("\n");
}
