import { constants } from "node:fs";
import type { Dirent } from "node:fs";
import {
  access,
  lstat,
  mkdir,
  mkdtemp,
  open,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { SourceOptions } from "../contracts.js";
import type { CollectedFile, CollectionIssue, SourceSnapshot } from "./types.js";

export const DEFAULT_MAX_FILES = 1_000;
export const DEFAULT_MAX_BYTES = 25 * 1024 * 1024;
export const DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024;
export const MAX_MAX_FILES = 10_000;
export const MAX_MAX_BYTES = 128 * 1024 * 1024;
export const MAX_MAX_FILE_BYTES = 8 * 1024 * 1024;

const IGNORED_DIRECTORIES = new Set([
  ".git",
  ".hg",
  ".svn",
  "node_modules",
  ".venv",
  "venv",
  "__pycache__",
  ".pytest_cache",
  ".mypy_cache",
  ".ruff_cache",
  ".intent-review",
  "vendor",
  "dist",
  "build",
  "coverage",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  ".parcel-cache",
  "out",
]);

// These files can alter scanner behavior or cause a scanner to read beyond
// the snapshot. They are intentionally omitted from the staged directory.
const IGNORED_SCANNER_FILES = new Set([
  ".gitleaks.toml",
  ".gitleaksignore",
  ".bandit",
  "bandit.yaml",
  "bandit.yml",
  "bandit.toml",
  ".trivyignore",
  ".trivy.yaml",
  "trivy.yaml",
  "trivy.yml",
  ".osv-scanner.toml",
  ".osv-scanner.yaml",
  ".osv-scanner.yml",
  "osv-scanner.toml",
  "osv-scanner.yaml",
  "osv-scanner.yml",
]);

const IGNORED_OUTPUT_FILES = new Set(["report.json", "report.sarif", "report.md", "comparison.json", "comparison.md"]);

const CODE_EXTENSIONS = new Set([
  ".c",
  ".cc",
  ".cpp",
  ".cs",
  ".cts",
  ".go",
  ".h",
  ".hh",
  ".hpp",
  ".java",
  ".js",
  ".jsx",
  ".kt",
  ".mjs",
  ".mts",
  ".php",
  ".py",
  ".rb",
  ".rs",
  ".sh",
  ".swift",
  ".ts",
  ".tsx",
  ".vue",
]);

const TEXT_EXTENSIONS = new Set([
  ".conf",
  ".graphql",
  ".gql",
  ".htm",
  ".html",
  ".ini",
  ".md",
  ".properties",
  ".proto",
  ".sql",
  ".svg",
  ".template",
  ".text",
  ".toml",
  ".txt",
  ".xml",
]);

const CONFIG_EXTENSIONS = new Set([
  ".dockerfile",
  ".hcl",
  ".tf",
  ".tfvars",
  ".yaml",
  ".yml",
  ".json",
  ".jsonc",
]);

const DEPENDENCY_BASENAMES = new Set([
  "bun.lock",
  "cargo.lock",
  "cargo.toml",
  "composer.json",
  "composer.lock",
  "deno.lock",
  "gemfile",
  "gemfile.lock",
  "go.mod",
  "go.sum",
  "package-lock.json",
  "package.json",
  "pipfile",
  "pipfile.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "pyproject.toml",
  "requirements.txt",
  "requirements-dev.txt",
  "requirements-prod.txt",
  "uv.lock",
  "npm-shrinkwrap.json",
  "yarn.lock",
]);

const SECRET_BASENAMES = new Set([
  ".aws/credentials",
  ".dockerconfigjson",
  ".npmrc",
  ".pypirc",
  ".yarnrc",
  ".yarnrc.yml",
]);

const SENSITIVE_SUFFIXES = /(?:\.pem|\.key|\.p12|\.pfx|\.jks|\.keystore|\.der)$/i;

export interface CollectorLimits {
  maxFiles: number;
  maxBytes: number;
  maxFileBytes: number;
}

function positiveBound(value: number | undefined, fallback: number, maximum: number): number {
  if (value === undefined) return fallback;
  if (!Number.isSafeInteger(value) || value <= 0) return fallback;
  return Math.min(value, maximum);
}

export function limitsFromOptions(options: Pick<SourceOptions, "maxFiles" | "maxBytes">): CollectorLimits {
  return {
    maxFiles: positiveBound(options.maxFiles, DEFAULT_MAX_FILES, MAX_MAX_FILES),
    maxBytes: positiveBound(options.maxBytes, DEFAULT_MAX_BYTES, MAX_MAX_BYTES),
    maxFileBytes: DEFAULT_MAX_FILE_BYTES,
  };
}

function issue(code: CollectionIssue["code"], path: string): CollectionIssue {
  return { code, path: path || "." };
}

function safeRelativePath(root: string, fullPath: string): string | undefined {
  const value = relative(root, fullPath).replaceAll(sep, "/");
  if (!value || value === "." || value.startsWith("../") || value === ".." || isAbsolute(value)) return undefined;
  const pieces = value.split("/");
  if (pieces.some((piece) => piece === "" || piece === "." || piece === "..")) return undefined;
  return pieces.join("/");
}

function basename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1).toLowerCase();
}

function extension(path: string): string {
  const name = basename(path);
  const index = name.lastIndexOf(".");
  return index < 0 ? "" : name.slice(index);
}

function isDotEnv(path: string): boolean {
  const name = basename(path);
  return name === ".env" || name.startsWith(".env.") || name.endsWith(".env");
}

function scannerFile(path: string): boolean {
  const name = basename(path);
  return IGNORED_SCANNER_FILES.has(name) || IGNORED_SCANNER_FILES.has(path.toLowerCase());
}

function classify(path: string): CollectedFile["category"] | undefined {
  const name = basename(path);
  const ext = extension(path);
  if (scannerFile(path)) return undefined;
  if (isDotEnv(path) || SECRET_BASENAMES.has(name) || path.toLowerCase().endsWith("/.aws/credentials") || SENSITIVE_SUFFIXES.test(name)) return "secret";
  if (DEPENDENCY_BASENAMES.has(name)) return "dependency";
  if (CODE_EXTENSIONS.has(ext)) return "code";
  if (CONFIG_EXTENSIONS.has(ext) || name === "dockerfile") return "config";
  if (TEXT_EXTENSIONS.has(ext)) return "text";
  return undefined;
}

function isFatalIssue(code: CollectionIssue["code"]): boolean {
  return code !== "unsupported_file";
}

function sameFile(before: StatsLike, after: StatsLike): boolean {
  return before.dev === after.dev && before.ino === after.ino && before.nlink === after.nlink && before.size === after.size;
}

interface StatsLike {
  dev: number;
  ino: number;
  nlink: number;
  size: number;
  isFile(): boolean;
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
}

async function readRegularFile(fullPath: string, expected: StatsLike, maxFileBytes: number): Promise<{ text?: string; issue?: CollectionIssue }> {
  let handle: Awaited<ReturnType<typeof open>> | undefined;
  try {
    // O_NOFOLLOW is supported on the macOS/Linux runners. Keeping the
    // fallback at zero still leaves the lstat/fstat identity checks active on
    // platforms that do not expose the constant.
    const noFollow = (constants as typeof constants & { O_NOFOLLOW?: number }).O_NOFOLLOW ?? 0;
    handle = await open(fullPath, constants.O_RDONLY | noFollow);
    const opened = await handle.stat() as unknown as StatsLike;
    if (opened.isSymbolicLink() || !opened.isFile() || opened.nlink > 1 || !sameFile(expected, opened)) {
      return { issue: issue("changed_file", "") };
    }
    if (opened.size < 0 || opened.size > maxFileBytes) return { issue: issue("size_limit", "") };
    const buffer = Buffer.allocUnsafe(opened.size);
    const read = await handle.read({ buffer, offset: 0, length: opened.size, position: 0 });
    const after = await handle.stat() as unknown as StatsLike;
    if (read.bytesRead !== opened.size || !sameFile(opened, after)) return { issue: issue("changed_file", "") };
    if (buffer.includes(0)) return { issue: issue("unsupported_file", "") };
    return { text: new TextDecoder("utf-8", { fatal: false }).decode(buffer) };
  } catch {
    return { issue: issue("read_error", "") };
  } finally {
    try {
      await handle?.close();
    } catch {
      // A failed close must not make a safe snapshot appear successful.
    }
  }
}

function outputPathRelative(root: string, outDir: string | undefined): string | undefined {
  if (!outDir) return undefined;
  const output = resolve(outDir);
  const candidate = safeRelativePath(root, output);
  if (candidate) return candidate;
  // The report directory may be the root itself or outside it. Only an output
  // directory inside the source tree is relevant to traversal.
  return undefined;
}

/**
 * Collects a bounded, allowlisted source snapshot. The collector opens only
 * ordinary files selected by `classify`, rejects symlinks/hardlinks, and
 * verifies the file identity before and after reading it.
 */
export async function collectSource(options: Pick<SourceOptions, "root" | "maxFiles" | "maxBytes" | "outDir">): Promise<SourceSnapshot> {
  const root = resolve(options.root);
  const limits = limitsFromOptions(options);
  const issues: CollectionIssue[] = [];
  const files: CollectedFile[] = [];
  let ignoredFiles = 0;
  let totalBytes = 0;
  // `maxFiles` bounds accepted allowlisted files. Excluded directories,
  // scanner configuration, generated output, and unknown extensions do not
  // consume that budget; `maxEntries` remains the independent traversal cap.
  let selectedFiles = 0;
  let inspectedEntries = 0;
  const maxEntries = Math.min(Math.max(limits.maxFiles * 8, 1_000), 100_000);
  let rootError: string | undefined;
  const outputRelative = outputPathRelative(root, options.outDir);

  let rootStat: StatsLike;
  try {
    rootStat = await lstat(root) as unknown as StatsLike;
  } catch {
    issues.push(issue("root_error", "."));
    rootError = "source root cannot be read";
    return { root, files, issues, ignoredFiles, totalBytes, complete: false, rootError };
  }
  if (rootStat.isSymbolicLink()) {
    issues.push(issue("root_error", "."));
    rootError = "source root must not be a symlink";
    return { root, files, issues, ignoredFiles, totalBytes, complete: false, rootError };
  }
  if (!rootStat.isDirectory()) {
    issues.push(issue("root_error", "."));
    rootError = "source root must be a directory";
    return { root, files, issues, ignoredFiles, totalBytes, complete: false, rootError };
  }

  const visit = async (directory: string, depth: number): Promise<void> => {
    if (depth > 64) {
      issues.push(issue("file_limit", safeRelativePath(root, directory) ?? "."));
      return;
    }
    let entries: Dirent<string>[];
    try {
      entries = await readdir(directory, { withFileTypes: true, encoding: "utf8" }) as unknown as Dirent<string>[];
    } catch {
      issues.push(issue("read_error", safeRelativePath(root, directory) ?? "."));
      return;
    }
    entries.sort((left, right) => left.name.localeCompare(right.name));
    for (const entry of entries) {
      inspectedEntries += 1;
      if (inspectedEntries > maxEntries) {
        issues.push(issue("file_limit", safeRelativePath(root, directory) ?? "."));
        return;
      }
      const fullPath = join(directory, entry.name);
      const path = safeRelativePath(root, fullPath);
      if (!path) {
        issues.push(issue("path_error", "."));
        continue;
      }
      if (entry.isDirectory()) {
        if (IGNORED_DIRECTORIES.has(entry.name.toLowerCase())) {
          ignoredFiles += 1;
          continue;
        }
        if (outputRelative && (path === outputRelative || path.startsWith(`${outputRelative}/`))) {
          ignoredFiles += 1;
          continue;
        }
        let directoryStat: StatsLike;
        try {
          directoryStat = await lstat(fullPath) as unknown as StatsLike;
        } catch {
          issues.push(issue("read_error", path));
          continue;
        }
        if (directoryStat.isSymbolicLink()) {
          issues.push(issue("symlink", path));
          continue;
        }
        if (!directoryStat.isDirectory()) {
          issues.push(issue("special_file", path));
          continue;
        }
        await visit(fullPath, depth + 1);
        continue;
      }
      if (entry.isSymbolicLink()) {
        issues.push(issue("symlink", path));
        continue;
      }
      if (IGNORED_OUTPUT_FILES.has(entry.name.toLowerCase())) {
        ignoredFiles += 1;
        continue;
      }
      let stat: StatsLike;
      try {
        stat = await lstat(fullPath) as unknown as StatsLike;
      } catch {
        issues.push(issue("read_error", path));
        continue;
      }
      if (stat.isSymbolicLink()) {
        issues.push(issue("symlink", path));
        continue;
      }
      if (!stat.isFile()) {
        issues.push(issue("special_file", path));
        continue;
      }
      if (stat.nlink > 1) {
        issues.push(issue("hardlink", path));
        continue;
      }
      const category = classify(path);
      if (!category) {
        ignoredFiles += 1;
        // An unknown extension is outside the explicit static-analysis
        // allowlist and does not need to be opened merely to classify it.
        continue;
      }
      if (selectedFiles >= limits.maxFiles) {
        issues.push(issue("file_limit", path));
        return;
      }
      selectedFiles += 1;
      if (stat.size > limits.maxFileBytes || totalBytes + stat.size > limits.maxBytes) {
        issues.push(issue("size_limit", path));
        continue;
      }
      const result = await readRegularFile(fullPath, stat, limits.maxFileBytes);
      if (result.text === undefined) {
        const code = result.issue?.code ?? "read_error";
        issues.push(issue(code, path));
        continue;
      }
      const bytes = Buffer.byteLength(result.text, "utf8");
      if (bytes > limits.maxFileBytes || totalBytes + bytes > limits.maxBytes) {
        issues.push(issue("size_limit", path));
        continue;
      }
      totalBytes += bytes;
      files.push({ path, bytes, text: result.text, category, sensitive: category === "secret" || isDotEnv(path) });
    }
  };

  await visit(root, 0);
  const complete = rootError === undefined && issues.every((entry) => !isFatalIssue(entry.code));
  return { root, files, issues, ignoredFiles, totalBytes, complete, ...(rootError ? { rootError } : {}) };
}

export interface StagedSnapshot {
  dir: string;
  cleanup: () => Promise<void>;
}

/**
 * Materializes only accepted files into a private temporary directory for
 * external scanners. The target tree is never passed to a scanner directly.
 */
export async function stageSnapshot(snapshot: SourceSnapshot): Promise<StagedSnapshot> {
  const parent = await mkdtemp(join(tmpdir(), "wakeio-security-ci-"));
  const dir = join(parent, "snapshot");
  await mkdir(dir, { recursive: true, mode: 0o700 });
  try {
    for (const file of snapshot.files) {
      const destination = join(dir, ...file.path.split("/"));
      await mkdir(dirname(destination), { recursive: true, mode: 0o700 });
      await writeFile(destination, file.text, { encoding: "utf8", mode: 0o600, flag: "wx" });
    }
  } catch (error) {
    await rm(parent, { recursive: true, force: true });
    throw error;
  }
  return {
    dir,
    cleanup: async () => {
      await rm(parent, { recursive: true, force: true });
    },
  };
}

export async function isExecutable(filePath: string): Promise<boolean> {
  try {
    const stat = await lstat(filePath);
    if (!stat.isFile()) return false;
    await access(filePath, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}
