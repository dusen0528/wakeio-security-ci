import type { CheckResult, ToolName } from "../contracts.js";

/**
 * A file that has passed the source collector's path, size, and file-type
 * policy. The text is kept only for the duration of a scan; it is never put
 * into a CheckResult or report.
 */
export interface CollectedFile {
  path: string;
  bytes: number;
  text: string;
  category: "code" | "dependency" | "config" | "text" | "secret";
  sensitive: boolean;
}

export interface CollectionIssue {
  code:
    | "root_error"
    | "read_error"
    | "symlink"
    | "hardlink"
    | "special_file"
    | "size_limit"
    | "file_limit"
    | "unsupported_file"
    | "path_error"
    | "changed_file";
  path: string;
}

export interface SourceSnapshot {
  root: string;
  files: CollectedFile[];
  issues: CollectionIssue[];
  ignoredFiles: number;
  totalBytes: number;
  complete: boolean;
  rootError?: string;
}

export interface ProcessResult {
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  outputLimitExceeded: boolean;
  spawnError?: string;
}

export interface ToolRunContext {
  snapshot: SourceSnapshot;
  stageDir: string;
  timeoutMs: number;
  toolName: ToolName;
  toolPath: string;
}

export interface ParsedToolResult {
  findings: CheckResult["findings"];
  notes: string[];
  metrics?: Record<string, number | string | boolean>;
  /** A strict parser may recognize a valid scanner envelope with no applicable input. */
  status?: CheckResult["status"];
}
