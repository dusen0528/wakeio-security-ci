export const SEQUENCE_DB_COLUMNS = {
  sequence_steps: [
    'run_id', 'sequence_id', 'reset_generation', 'ordinal', 'state_scope', 'operation_ref',
    'surface_id', 'method', 'actor_ref', 'plan_digest',
  ],
  planned_cells: [
    'run_id', 'sequence_id', 'reset_generation', 'surface_id', 'check_id', 'actor_ref', 'ordinal',
    'first_iteration', 'plan_digest', 'execution_state', 'observation_outcome', 'task_id', 'reason_code',
  ],
  observation_refs: [
    'run_id', 'observation_id', 'sequence_id', 'reset_generation', 'surface_id', 'check_id', 'actor_ref',
    'ordinal', 'admission_id', 'channel_ref', 'evidence_ref', 'content_hash', 'logical_ordinal',
  ],
  edges: [
    'run_id', 'sequence_id', 'reset_generation', 'producer_ordinal', 'consumer_ordinal', 'kind',
    'extraction_ref', 'destination_location', 'destination_ref', 'provenance', 'scalar_type', 'value_type',
    'producer_observation_id', 'consumer_observation_id',
  ],
} as const;

export const SEQUENCE_DB_INTEGRITY_QUERIES = [
  'SELECT 1 FROM sequence_steps s JOIN surface f ON f.surface_id=s.surface_id'
    + ' WHERE f.run_id<>s.run_id LIMIT 1',
  'SELECT 1 FROM planned_cells c JOIN sequence_steps s ON s.run_id=c.run_id'
    + ' AND s.sequence_id=c.sequence_id AND s.reset_generation=c.reset_generation AND s.ordinal=c.ordinal'
    + ' LEFT JOIN tasks t ON t.task_id=c.task_id'
    + ' WHERE c.plan_digest<>s.plan_digest OR (c.task_id IS NOT NULL AND t.run_id<>c.run_id) LIMIT 1',
  "SELECT 1 FROM edges e LEFT JOIN observation_refs p ON p.run_id=e.run_id"
    + ' AND p.observation_id=e.producer_observation_id LEFT JOIN observation_refs c ON c.run_id=e.run_id'
    + " AND c.observation_id=e.consumer_observation_id WHERE e.provenance='observed' AND ("
    + ' p.observation_id IS NULL OR c.observation_id IS NULL OR p.sequence_id<>e.sequence_id'
    + ' OR c.sequence_id<>e.sequence_id OR p.reset_generation<>e.reset_generation'
    + ' OR c.reset_generation<>e.reset_generation OR p.ordinal<>e.producer_ordinal'
    + ' OR c.ordinal<>e.consumer_ordinal) LIMIT 1',
] as const;

export const SEQUENCE_DB_MIGRATION = `
CREATE TABLE sequence_steps (
  run_id TEXT NOT NULL CHECK(length(CAST(run_id AS BLOB)) BETWEEN 1 AND 42 AND instr(run_id,char(0))=0),
  sequence_id TEXT NOT NULL,
  reset_generation INTEGER NOT NULL CHECK(reset_generation BETWEEN 1 AND 9007199254740991),
  ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15),
  state_scope TEXT NOT NULL,
  operation_ref TEXT NOT NULL,
  surface_id TEXT NOT NULL CHECK(length(CAST(surface_id AS BLOB)) BETWEEN 1 AND 62 AND instr(surface_id,char(0))=0),
  method TEXT NOT NULL CHECK(method IN ('GET','HEAD','POST','PUT','PATCH','DELETE')),
  actor_ref TEXT NOT NULL,
  plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'),
  PRIMARY KEY(run_id,sequence_id,reset_generation,ordinal),
  UNIQUE(run_id,sequence_id,reset_generation,ordinal,surface_id,actor_ref),
  FOREIGN KEY(run_id) REFERENCES runs(run_id),
  FOREIGN KEY(surface_id) REFERENCES surface(surface_id),
  CHECK(length(CAST(sequence_id AS BLOB)) BETWEEN 1 AND 40 AND instr(sequence_id,char(0))=0
    AND sequence_id GLOB '[a-z]*' AND sequence_id NOT GLOB '*[^a-z0-9_-]*'
    AND sequence_id NOT IN ('constructor','prototype')),
  CHECK(length(CAST(state_scope AS BLOB)) BETWEEN 1 AND 40 AND instr(state_scope,char(0))=0
    AND state_scope GLOB '[a-z]*' AND state_scope NOT GLOB '*[^a-z0-9_-]*'
    AND state_scope NOT IN ('constructor','prototype')),
  CHECK(length(CAST(operation_ref AS BLOB)) BETWEEN 1 AND 40 AND instr(operation_ref,char(0))=0
    AND operation_ref GLOB '[a-z]*' AND operation_ref NOT GLOB '*[^a-z0-9_-]*'
    AND operation_ref NOT IN ('constructor','prototype')),
  CHECK(length(CAST(actor_ref AS BLOB)) BETWEEN 1 AND 40 AND instr(actor_ref,char(0))=0
    AND actor_ref GLOB '[a-z]*' AND actor_ref NOT GLOB '*[^a-z0-9_-]*'
    AND actor_ref NOT IN ('constructor','prototype'))
) STRICT;
CREATE TABLE planned_cells (
  run_id TEXT NOT NULL CHECK(length(CAST(run_id AS BLOB)) BETWEEN 1 AND 42 AND instr(run_id,char(0))=0),
  sequence_id TEXT NOT NULL,
  reset_generation INTEGER NOT NULL CHECK(reset_generation BETWEEN 1 AND 9007199254740991),
  surface_id TEXT NOT NULL CHECK(length(CAST(surface_id AS BLOB)) BETWEEN 1 AND 62 AND instr(surface_id,char(0))=0),
  check_id TEXT NOT NULL,
  actor_ref TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15),
  first_iteration INTEGER NOT NULL CHECK(first_iteration BETWEEN 1 AND 64),
  plan_digest TEXT NOT NULL CHECK(length(plan_digest)=64 AND plan_digest NOT GLOB '*[^0-9a-f]*'),
  execution_state TEXT NOT NULL
    CHECK(execution_state IN ('queued','running','completed','partial','error','not_applicable','skipped')),
  observation_outcome TEXT NOT NULL CHECK(observation_outcome IN ('observed','not_observed','unverified')),
  task_id TEXT CHECK(task_id IS NULL OR
    (length(CAST(task_id AS BLOB)) BETWEEN 1 AND 62 AND instr(task_id,char(0))=0)),
  reason_code TEXT CHECK(reason_code IS NULL OR reason_code IN (
    'cancelled','tool_error','policy_denied','observer_unavailable','reset_failed','budget_exhausted',
    'iteration_limit','no_progress','dependency_failed','extraction_missing','extraction_limit','type_mismatch',
    'stale_generation','private_value_limit','not_applicable','not_observed','interrupted')),
  PRIMARY KEY(run_id,sequence_id,reset_generation,surface_id,check_id,actor_ref,ordinal),
  FOREIGN KEY(run_id,sequence_id,reset_generation,ordinal,surface_id,actor_ref)
    REFERENCES sequence_steps(run_id,sequence_id,reset_generation,ordinal,surface_id,actor_ref),
  FOREIGN KEY(task_id) REFERENCES tasks(task_id),
  CHECK(length(CAST(sequence_id AS BLOB)) BETWEEN 1 AND 40 AND instr(sequence_id,char(0))=0
    AND sequence_id GLOB '[a-z]*' AND sequence_id NOT GLOB '*[^a-z0-9_-]*'
    AND sequence_id NOT IN ('constructor','prototype')),
  CHECK(length(CAST(check_id AS BLOB)) BETWEEN 1 AND 40 AND instr(check_id,char(0))=0
    AND check_id GLOB '[a-z]*' AND check_id NOT GLOB '*[^a-z0-9_-]*'
    AND check_id NOT IN ('constructor','prototype')),
  CHECK(length(CAST(actor_ref AS BLOB)) BETWEEN 1 AND 40 AND instr(actor_ref,char(0))=0
    AND actor_ref GLOB '[a-z]*' AND actor_ref NOT GLOB '*[^a-z0-9_-]*'
    AND actor_ref NOT IN ('constructor','prototype')),
  CHECK(execution_state NOT IN ('queued','running') OR
    (observation_outcome='unverified' AND reason_code IS NULL)),
  CHECK(execution_state NOT IN ('partial','error','skipped') OR reason_code IS NOT NULL),
  CHECK(execution_state!='not_applicable' OR
    (reason_code IS NOT NULL AND reason_code='not_applicable'))
) STRICT;
CREATE TABLE observation_refs (
  run_id TEXT NOT NULL CHECK(length(CAST(run_id AS BLOB)) BETWEEN 1 AND 42 AND instr(run_id,char(0))=0),
  observation_id TEXT NOT NULL
    CHECK(length(CAST(observation_id AS BLOB)) BETWEEN 1 AND 200 AND instr(observation_id,char(0))=0),
  sequence_id TEXT NOT NULL,
  reset_generation INTEGER NOT NULL CHECK(reset_generation BETWEEN 1 AND 9007199254740991),
  surface_id TEXT NOT NULL CHECK(length(CAST(surface_id AS BLOB)) BETWEEN 1 AND 62 AND instr(surface_id,char(0))=0),
  check_id TEXT NOT NULL,
  actor_ref TEXT NOT NULL,
  ordinal INTEGER NOT NULL CHECK(ordinal BETWEEN 0 AND 15),
  admission_id TEXT NOT NULL
    CHECK(length(CAST(admission_id AS BLOB)) BETWEEN 1 AND 200 AND instr(admission_id,char(0))=0),
  channel_ref TEXT NOT NULL,
  evidence_ref TEXT NOT NULL
    CHECK(length(CAST(evidence_ref AS BLOB)) BETWEEN 1 AND 200 AND instr(evidence_ref,char(0))=0),
  content_hash TEXT NOT NULL CHECK(length(content_hash)=64 AND content_hash NOT GLOB '*[^0-9a-f]*'),
  logical_ordinal INTEGER NOT NULL CHECK(logical_ordinal BETWEEN 1 AND 9007199254740991),
  PRIMARY KEY(run_id,observation_id),
  UNIQUE(run_id,sequence_id,reset_generation,ordinal,check_id,channel_ref,logical_ordinal),
  FOREIGN KEY(run_id,sequence_id,reset_generation,surface_id,check_id,actor_ref,ordinal)
    REFERENCES planned_cells(run_id,sequence_id,reset_generation,surface_id,check_id,actor_ref,ordinal),
  CHECK(length(CAST(sequence_id AS BLOB)) BETWEEN 1 AND 40 AND instr(sequence_id,char(0))=0
    AND sequence_id GLOB '[a-z]*' AND sequence_id NOT GLOB '*[^a-z0-9_-]*'
    AND sequence_id NOT IN ('constructor','prototype')),
  CHECK(length(CAST(check_id AS BLOB)) BETWEEN 1 AND 40 AND instr(check_id,char(0))=0
    AND check_id GLOB '[a-z]*' AND check_id NOT GLOB '*[^a-z0-9_-]*'
    AND check_id NOT IN ('constructor','prototype')),
  CHECK(length(CAST(actor_ref AS BLOB)) BETWEEN 1 AND 40 AND instr(actor_ref,char(0))=0
    AND actor_ref GLOB '[a-z]*' AND actor_ref NOT GLOB '*[^a-z0-9_-]*'
    AND actor_ref NOT IN ('constructor','prototype')),
  CHECK(length(CAST(channel_ref AS BLOB)) BETWEEN 1 AND 40 AND instr(channel_ref,char(0))=0
    AND channel_ref GLOB '[a-z]*' AND channel_ref NOT GLOB '*[^a-z0-9_-]*'
    AND channel_ref NOT IN ('constructor','prototype'))
) STRICT;
CREATE TABLE edges (
  run_id TEXT NOT NULL CHECK(length(CAST(run_id AS BLOB)) BETWEEN 1 AND 42 AND instr(run_id,char(0))=0),
  sequence_id TEXT NOT NULL,
  reset_generation INTEGER NOT NULL CHECK(reset_generation BETWEEN 1 AND 9007199254740991),
  producer_ordinal INTEGER NOT NULL CHECK(producer_ordinal BETWEEN 0 AND 15),
  consumer_ordinal INTEGER NOT NULL CHECK(consumer_ordinal BETWEEN 0 AND 15),
  kind TEXT NOT NULL CHECK(kind IN ('prerequisite','binding')),
  extraction_ref TEXT NOT NULL,
  destination_location TEXT NOT NULL,
  destination_ref TEXT NOT NULL,
  provenance TEXT NOT NULL CHECK(provenance IN ('declared','inferred','observed')),
  scalar_type TEXT,
  value_type TEXT,
  producer_observation_id TEXT,
  consumer_observation_id TEXT,
  PRIMARY KEY(run_id,sequence_id,reset_generation,producer_ordinal,consumer_ordinal,kind,
    extraction_ref,destination_location,destination_ref),
  FOREIGN KEY(run_id,sequence_id,reset_generation,producer_ordinal)
    REFERENCES sequence_steps(run_id,sequence_id,reset_generation,ordinal),
  FOREIGN KEY(run_id,sequence_id,reset_generation,consumer_ordinal)
    REFERENCES sequence_steps(run_id,sequence_id,reset_generation,ordinal),
  FOREIGN KEY(run_id,producer_observation_id) REFERENCES observation_refs(run_id,observation_id),
  FOREIGN KEY(run_id,consumer_observation_id) REFERENCES observation_refs(run_id,observation_id),
  CHECK(producer_ordinal<consumer_ordinal),
  CHECK(length(CAST(sequence_id AS BLOB)) BETWEEN 1 AND 40 AND instr(sequence_id,char(0))=0
    AND sequence_id GLOB '[a-z]*' AND sequence_id NOT GLOB '*[^a-z0-9_-]*'
    AND sequence_id NOT IN ('constructor','prototype')),
  CHECK(
    (kind='prerequisite' AND extraction_ref='' AND destination_location='' AND destination_ref=''
      AND scalar_type IS NULL AND value_type IS NULL
      AND producer_observation_id IS NULL AND consumer_observation_id IS NULL AND provenance='declared')
    OR
    (kind='binding'
      AND length(CAST(extraction_ref AS BLOB)) BETWEEN 1 AND 40 AND instr(extraction_ref,char(0))=0
      AND extraction_ref GLOB '[a-z]*' AND extraction_ref NOT GLOB '*[^a-z0-9_-]*'
      AND extraction_ref NOT IN ('constructor','prototype')
      AND scalar_type IS NOT NULL AND scalar_type IN ('string','number','boolean','null')
      AND value_type IS NOT NULL
      AND length(CAST(value_type AS BLOB)) BETWEEN 1 AND 40 AND instr(value_type,char(0))=0
      AND value_type GLOB '[a-z]*' AND value_type NOT GLOB '*[^a-z0-9_-]*'
      AND value_type NOT IN ('constructor','prototype')
      AND (
        (destination_location='body' AND length(CAST(destination_ref AS BLOB)) BETWEEN 1 AND 4096
          AND instr(destination_ref,char(0))=0)
        OR
        (destination_location IN ('path','query','header','cookie')
          AND length(CAST(destination_ref AS BLOB)) BETWEEN 1 AND 40 AND instr(destination_ref,char(0))=0
          AND destination_ref GLOB '[a-z]*' AND destination_ref NOT GLOB '*[^a-z0-9_-]*'
          AND destination_ref NOT IN ('constructor','prototype'))
      )
      AND (
        (provenance IN ('declared','inferred')
          AND producer_observation_id IS NULL AND consumer_observation_id IS NULL)
        OR
        (provenance='observed' AND producer_observation_id IS NOT NULL AND consumer_observation_id IS NOT NULL
          AND length(CAST(producer_observation_id AS BLOB)) BETWEEN 1 AND 200
          AND instr(producer_observation_id,char(0))=0
          AND length(CAST(consumer_observation_id AS BLOB)) BETWEEN 1 AND 200
          AND instr(consumer_observation_id,char(0))=0)
      )
    )
  )
) STRICT;
`;
