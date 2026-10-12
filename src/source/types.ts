import type { CheckResult, CollectionBudget, CollectionIssueCode, ToolName } from "../contracts.js";

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
  code: CollectionIssueCode;
  path: string;
}

export interface SourceSnapshot {
  /** Always supplied by collectSource; optional for synthetic/legacy snapshots. */
  collectionBudget?: CollectionBudget;
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
  cancelled?: boolean;
  stopReason?: 'cancelled' | 'timeout' | 'output_limit' | 'rss_limit' | 'observer_unknown' | 'spawn_error' | 'close_unknown';
  exited?: boolean;
  closeConfirmed?: boolean;
  cleanupState?: 'terminated' | 'terminated_zombies' | 'running' | 'unknown' | 'not_started';
  cleanupConfirmed?: boolean;
  rss?: { assessment: 'measured' | 'unassessed'; samples: number; failedSamples: number; peakBytes: number; capBytes: number };
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
