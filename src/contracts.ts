export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Mode = 'source' | 'url' | 'both' | 'api' | 'combined';
export type ToolName = 'gitleaks' | 'osv' | 'trivy' | 'bandit';
export interface Finding {
  /** Deterministic report identity; changes when the rule or location changes. */
  id?: string;
  /** Optional stable semantic anchor used by report comparison across line moves. */
  comparisonKey?: string;
  ruleId: string;
  title: string;
  description: string;
  severity: Severity;
  confidence: 'low' | 'medium' | 'high';
  kind: 'observation' | 'candidate' | 'advisory';
  location: { path?: string; url?: string; line?: number; column?: number };
  remediation: string;
  references?: string[];
}
export interface CheckResult {
  id: string;
  status: 'completed' | 'partial' | 'error' | 'not_applicable' | 'skipped';
  findings: Finding[];
  notes: string[];
  metrics?: Record<string, number | string | boolean>;
}
export interface SourceOptions {
  root: string;
  tools: ToolName[];
  toolPaths?: Partial<Record<ToolName, string>>;
  timeoutMs?: number;
  maxFiles?: number;
  maxBytes?: number;
  osvOffline?: boolean;
  outDir?: string;
}
export interface UrlOptions {
  url: string;
  /** Optional additional same-origin pages. The root `url` is always scanned first. */
  pages?: string[];
  allowPrivate?: boolean;
  timeoutMs?: number;
  maxPages?: number;
  maxScripts?: number;
  maxBytes?: number;
}

export interface EngineProvenance {
  name: string;
  status: 'available' | 'missing' | 'unreadable' | 'unknown';
  sha256?: string;
}

export interface ScanProvenance {
  /** Evidence about the scanned input; it is deliberately excluded from scope identity. */
  sourceContentHash?: string;
  engines?: EngineProvenance[];
  /** Scanner database or rule bundle state. Unknown is explicit and not equivalent to fixed. */
  dataSources?: Record<string, string>;
}

export interface ScanScope {
  fingerprint: string;
  ruleset: string;
  /** Logical repository/project identity; allows different checkout paths to compare. */
  projectId?: string;
  provenance?: ScanProvenance;
}

export interface ScanReport {
  schemaVersion: '1.0.0';
  toolVersion: string;
  mode: Mode;
  startedAt: string;
  finishedAt: string;
  checks: CheckResult[];
  scope?: ScanScope;
}
