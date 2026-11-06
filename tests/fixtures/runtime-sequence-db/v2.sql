CREATE TABLE runs (
  run_id TEXT PRIMARY KEY, target_origin TEXT NOT NULL, scope_hash TEXT NOT NULL,
  provider TEXT NOT NULL CHECK(provider IN ('codex','claude','mixed','fixed')),
  started_at TEXT NOT NULL, finished_at TEXT,
  status TEXT NOT NULL CHECK(status IN ('running','completed','partial','error'))
);
CREATE TABLE surface (
  surface_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
  method TEXT NOT NULL, path TEXT NOT NULL, param TEXT,
  location TEXT CHECK(location IN ('query','body','header','path','cookie')),
  auth_state TEXT NOT NULL CHECK(auth_state IN ('anonymous','user','other_user','admin'))
);
CREATE TABLE tasks (
  task_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
  category TEXT NOT NULL CHECK(category IN ('recon','injection','authz','config','verify')),
  surface_ids TEXT NOT NULL, provider TEXT NOT NULL CHECK(provider IN ('codex','claude','mixed','fixed')),
  script_ref TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('queued','running','completed','partial','error','skipped')),
  next_hint TEXT, duration_ms INTEGER
);
CREATE TABLE task_gaps (
  task_id TEXT NOT NULL REFERENCES tasks(task_id),
  reason TEXT NOT NULL
    CHECK(reason IN ('auth_required','timeout','budget_exhausted','out_of_scope','tool_error','unsupported')),
  count INTEGER NOT NULL CHECK(count>=1), PRIMARY KEY(task_id,reason)
);
CREATE TABLE findings (
  finding_id TEXT PRIMARY KEY, run_id TEXT NOT NULL REFERENCES runs(run_id),
  task_id TEXT NOT NULL REFERENCES tasks(task_id), surface_id TEXT REFERENCES surface(surface_id),
  rule_id TEXT NOT NULL, severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')),
  state TEXT NOT NULL CHECK(state IN ('candidate','confirmed','rejected')),
  dedupe_key TEXT NOT NULL, evidence_ref TEXT NOT NULL, UNIQUE(run_id,dedupe_key)
);
CREATE TABLE coverage_plan (
  task_id TEXT NOT NULL REFERENCES tasks(task_id), surface_id TEXT NOT NULL REFERENCES surface(surface_id),
  "check" TEXT NOT NULL, PRIMARY KEY(task_id,surface_id,"check")
);
CREATE TABLE finding_observations (
  observation_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL REFERENCES findings(finding_id),
  task_id TEXT NOT NULL, surface_id TEXT NOT NULL, "check" TEXT NOT NULL,
  severity TEXT NOT NULL CHECK(severity IN ('critical','high','medium','low','info')), evidence_ref TEXT NOT NULL,
  FOREIGN KEY(task_id,surface_id,"check") REFERENCES coverage_plan(task_id,surface_id,"check")
);
CREATE TABLE coverage (
  task_id TEXT NOT NULL, surface_id TEXT NOT NULL, "check" TEXT NOT NULL,
  result TEXT NOT NULL CHECK(result IN ('executed','skipped','error')),
  reason TEXT CHECK(reason IS NULL OR
    reason IN ('auth_required','timeout','budget_exhausted','out_of_scope','tool_error','unsupported')),
  PRIMARY KEY(task_id,surface_id,"check"),
  FOREIGN KEY(task_id,surface_id,"check") REFERENCES coverage_plan(task_id,surface_id,"check")
);
CREATE TABLE ledger (
  task_id TEXT PRIMARY KEY REFERENCES tasks(task_id),
  provider TEXT NOT NULL CHECK(provider IN ('codex','claude','mixed','fixed')),
  input_tokens INTEGER, output_tokens INTEGER, request_count INTEGER NOT NULL DEFAULT 0,
  bytes INTEGER NOT NULL DEFAULT 0, exit_code INTEGER, stdout_bytes INTEGER NOT NULL DEFAULT 0,
  truncated INTEGER NOT NULL DEFAULT 0 CHECK(truncated IN (0,1))
);
CREATE INDEX idx_findings_state ON findings(run_id,state,severity);
CREATE INDEX idx_tasks_run ON tasks(run_id,status);
CREATE INDEX idx_coverage_result ON coverage(task_id,result);
CREATE INDEX idx_observations_task ON finding_observations(task_id,finding_id);
INSERT INTO runs VALUES('r-owned','http://127.0.0.1','old-scope','fixed','2026-11-05',NULL,'running');
INSERT INTO surface VALUES('s-owned','r-owned','GET','/owned','id','query','user');
INSERT INTO tasks VALUES('t-owned','r-owned','injection','["s-owned"]','fixed','owned.mjs','partial','verify',7);
INSERT INTO task_gaps VALUES('t-owned','timeout',2);
INSERT INTO findings VALUES('f-owned','r-owned','t-owned','s-owned','rule','low','candidate','old-key','evidence/a.json');
INSERT INTO coverage_plan VALUES('t-owned','s-owned','check');
INSERT INTO finding_observations VALUES('old-observation','f-owned','t-owned','s-owned','check','low','evidence/a.json');
INSERT INTO coverage VALUES('t-owned','s-owned','check','executed',NULL);
INSERT INTO ledger VALUES('t-owned','fixed',2,3,1,42,0,12,0);
PRAGMA user_version=2;
