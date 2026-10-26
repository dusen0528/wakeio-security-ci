import type { SourceSnapshot } from "./types.js";
import { inspectRequirementsFile } from "./requirements.js";

const OSV_LOCKFILE_NAMES = new Set([
  "package-lock.json",
  "npm-shrinkwrap.json",
  "yarn.lock",
  "pnpm-lock.yaml",
  "bun.lock",
  "bun.lockb",
  "cargo.lock",
  "go.sum",
  "gemfile.lock",
  "composer.lock",
  "pipfile.lock",
  "poetry.lock",
  "uv.lock",
  "deno.lock",
]);

const OSV_MANIFEST_NAMES = new Set([
  "package.json",
  "composer.json",
  "cargo.toml",
  "go.mod",
  "gemfile",
  "pipfile",
  "pyproject.toml",
  "requirements.txt",
  "requirements-dev.txt",
  "requirements-prod.txt",
]);

export function trivyInputCandidate(path: string, text: string): boolean {
  const lower = path.toLowerCase();
  const name = lower.slice(lower.lastIndexOf("/") + 1);
  if (name === "dockerfile" || name.endsWith(".dockerfile")) return true;
  if (/\.(?:yaml|yml)$/.test(lower)) return true;
  if (/\.(?:tf|tfvars|hcl)(?:\.json)?$/.test(lower)) return true;
  // Kubernetes manifests are also commonly stored as JSON. Generic JSON
  // (package metadata, tsconfig, editor settings) is excluded so it cannot
  // make Trivy appear applicable to an ordinary source project.
  if (!lower.endsWith(".json")) return false;
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const object = parsed as Record<string, unknown>;
    return typeof object.apiVersion === "string" && typeof object.kind === "string";
  } catch {
    return false;
  }
}

export function fileBasename(path: string): string {
  return path.slice(path.lastIndexOf("/") + 1).toLowerCase();
}

function packageManifestHasExplicitlyEmptyDependencies(text: string): boolean {
  try {
    const parsed = JSON.parse(text) as unknown;
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) return false;
    const object = parsed as Record<string, unknown>;
    const fields = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
      "bundledDependencies", "bundleDependencies"];
    if (!fields.some((key) => Object.prototype.hasOwnProperty.call(object, key))) return false;
    for (const key of ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies",
      "bundledDependencies", "bundleDependencies", "require", "require-dev"]) {
      const value = object[key];
      if (Array.isArray(value) && value.length > 0) return false;
      if (value !== undefined && (value === null || typeof value !== "object"
        || Object.keys(value as object).length > 0)) return false;
    }
    return true;
  } catch {
    return false;
  }
}

function dependencyManifestNeedsLockfile(file: SourceSnapshot["files"][number]): boolean {
  const name = fileBasename(file.path);
  // A known dependency manifest is an expected-input signal even when its
  // syntax is too rich for this bounded adapter to interpret. An explicit
  // empty package dependency map is the one safe exception.
  return name !== "package.json" || !packageManifestHasExplicitlyEmptyDependencies(file.text);
}

export function requirementsInspection(snapshot: SourceSnapshot): { pinned: string[]; unresolved: string[] } {
  const pinned: string[] = [];
  const unresolved: string[] = [];
  for (const file of snapshot.files) {
    if (file.category !== "dependency" || !/^requirements(?:-[^/]+)?\.txt$/i.test(fileBasename(file.path))) continue;
    if (inspectRequirementsFile(file.text).pinned) pinned.push(file.path);
    else unresolved.push(file.path);
  }
  return { pinned, unresolved };
}

export function osvLockfiles(snapshot: SourceSnapshot): string[] {
  const requirements = new Set(requirementsInspection(snapshot).pinned);
  return snapshot.files
    .filter((file) => file.category === "dependency"
      && (OSV_LOCKFILE_NAMES.has(fileBasename(file.path)) || requirements.has(file.path)))
    .map((file) => file.path);
}

export function osvManifestDeclaresDependencies(snapshot: SourceSnapshot): boolean {
  return snapshot.files.some((file) => file.category === "dependency"
    && OSV_MANIFEST_NAMES.has(fileBasename(file.path))
    && dependencyManifestNeedsLockfile(file));
}

export function osvHasApplicableInput(snapshot: SourceSnapshot): boolean {
  return osvLockfiles(snapshot).length > 0 || osvManifestDeclaresDependencies(snapshot);
}
