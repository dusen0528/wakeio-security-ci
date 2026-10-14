/** Read-only linkage for an existing run-plan bundle. No scanner or model calls. */
import { lstatSync, readFileSync, realpathSync } from 'node:fs';
import { resolve, sep } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { siteKey } from './labels.js';
import type { EvalFinding, EvidenceDoc } from './aggregate.js';

function bundleFile(root: string, relative: string): string {
  if (!/^(run\.db|evidence\/f-[0-9a-z-]{1,40}\.json|tasks\/t-[0-9a-z-]{1,60}\/report\.json)$/.test(relative)) throw Error('invalid_bundle_path');
  const base = realpathSync(root), path = resolve(base, relative);
  if (!path.startsWith(base + sep) || realpathSync(path) !== path || !lstatSync(path).isFile()) throw Error('invalid_bundle_file');
  return path;
}
function bytes(root: string, relative: string): Buffer {
  const path = bundleFile(root, relative);
  if (lstatSync(path).size > 16 * 1024 * 1024) throw Error('bundle_file_too_large');
  return readFileSync(path);
}

/** root is an owner-selected run-plan output directory, never a path from a finding. */
export function storedRunReader(root: string) {
  return {
    readEvidence(relative: string): Buffer | null {
      try { return bytes(root, relative); } catch { return null; }
    },
    verifyStoredFinding(finding: EvalFinding, evidence: EvidenceDoc): boolean {
      let db: DatabaseSync | undefined;
      try {
        if (!finding.runRef || evidence.taskId !== finding.runRef.taskId) return false;
        db = new DatabaseSync(bundleFile(root, 'run.db'), { readOnly: true });
        // The evidence filename identifies an observation; deduplication may give it a different canonical finding ID.
        const row = db.prepare(`SELECT t.run_id, o.task_id, o.evidence_ref, o.severity, f.rule_id,
          s.method, s.path, s.param, s.location, s.auth_state AS authState
          FROM finding_observations o JOIN findings f ON f.finding_id=o.finding_id
          JOIN tasks t ON t.task_id=o.task_id JOIN surface s ON s.surface_id=o.surface_id
          WHERE o.observation_id=? AND t.run_id=? AND o.task_id=? AND f.run_id=t.run_id AND s.run_id=t.run_id`)
          .get(finding.findingId, finding.runRef.runId, finding.runRef.taskId);
        if (!row || row.evidence_ref !== finding.evidenceRef || row.rule_id !== evidence.ruleId
          || row.severity !== evidence.severity || row.severity !== finding.severity
          || siteKey(row as unknown as Parameters<typeof siteKey>[0]) !== siteKey(finding)) return false;
        if (evidence.reportPath !== `tasks/${finding.runRef.taskId}/report.json`) return false;
        const report = JSON.parse(bytes(root, evidence.reportPath).toString('utf8'));
        if (!Array.isArray(report.checks)) return false;
        const matches = report.checks.flatMap((check: { findings?: unknown[] }) => Array.isArray(check.findings) ? check.findings : [])
          .filter((item: { id?: string }) => item && item.id === evidence.findingId);
        return matches.length === 1 && matches[0].ruleId === evidence.ruleId
          && matches[0].severity === evidence.severity && matches[0].kind === evidence.kind;
      } catch { return false; }
      finally { db?.close(); }
    },
  };
}
