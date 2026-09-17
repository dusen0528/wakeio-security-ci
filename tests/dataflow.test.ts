import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSource } from "../src/source.js";

async function scan(source: string, fileName = "app.ts") {
  const root = await mkdtemp(join(tmpdir(), "wakeio-security-ci-dataflow-"));
  try {
    await writeFile(join(root, fileName), source);
    const checks = await runSource({ root, tools: [] });
    return checks.find((check) => check.id === "source.builtin-ast");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("same-function aliases and destructured request parameters reach dynamic SQL", async () => {
  const ast = await scan(`
    function byId(req: any) {
      const id = req.params.id;
      const query = "select * from users where id = " + id;
      db.query(query);
    }
    function bySlug(req: any) {
      const { slug: routeSlug } = req.params;
      db.query(\`select * from posts where slug = \${routeSlug}\`);
    }
  `);

  assert.ok(ast);
  const sqlFindings = ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink");
  assert.equal(sqlFindings.length, 2);
  assert.ok(sqlFindings.every((finding) => finding.confidence === "medium"));
  assert.equal(JSON.stringify(ast).includes("req.params.id"), false);
});

test("fixed query text, fixed reassignment, and parameterized SQL stay clean", async () => {
  const ast = await scan(`
    function safe(req: any) {
      let id = req.params.id;
      id = "fixed";
      db.query("select * from users where id = " + id);
      db.query("select * from users where id = ?", [req.params.id]);
      db.query("select * from users where id = 7");
    }
  `);

  assert.ok(ast);
  assert.equal(ast.findings.some((finding) => finding.ruleId === "ast:sql-input-sink"), false);
});

test("an unknown sanitizer remains an input candidate with lower confidence", async () => {
  const ast = await scan(`
    function maybeSafe(req: any) {
      const id = req.params.id;
      const checked = sanitizeForSql(id);
      db.query("select * from users where id = " + checked);
    }
  `);

  assert.ok(ast);
  const finding = ast.findings.find((candidate) => candidate.ruleId === "ast:sql-input-sink");
  assert.ok(finding);
  assert.equal(finding.confidence, "low");
  assert.match(finding.kind, /candidate/);
});

test("conditional reassignment keeps a possible input flow, while a shadow does not clear the outer binding", async () => {
  const ast = await scan(`
    function branches(req: any) {
      let id = req.params.id;
      if (featureFlag) id = "fixed";
      db.query("select * from users where id = " + id);
      {
        const id = "local-fixed";
        db.query("select * from users where id = " + id);
      }
      db.query("select * from users where id = " + id);
    }
  `);

  assert.ok(ast);
  const sqlFindings = ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink");
  assert.equal(sqlFindings.length, 2);
  assert.ok(sqlFindings.every((finding) => finding.confidence === "low"));
});

test("comments and string-only request references do not create sink findings", async () => {
  const ast = await scan(`
    function textOnly(req: any) {
      const note = "req.params.id";
      db.query("select * from users where id = 1 /* req.params.id */");
      document.body.innerHTML = "location.search";
      return note;
    }
  `);

  assert.ok(ast);
  assert.equal(ast.findings.some((finding) => /ast:(?:sql-input-sink|html-input-sink|open-redirect)/.test(finding.ruleId)), false);
});

test("loop shadowing and fallback expressions preserve the outer possible flow", async () => {
  const ast = await scan(`
    function loops(req: any) {
      let id = req.params.id;
      for (let id = 0; id < 1; id += 1) { }
      const fallback = id || "fixed";
      db.query("select * from users where id = " + fallback);
    }
  `);

  assert.ok(ast);
  const finding = ast.findings.find((candidate) => candidate.ruleId === "ast:sql-input-sink");
  assert.ok(finding);
  assert.equal(finding.confidence, "low");
});

test("unsupported destructuring targets are ignored without crashing the scan", async () => {
  const ast = await scan(`
    function unsupported(req: any) {
      let value = "fixed";
      ({ value: object.field } = req.params);
      db.query("select * from users where id = " + value);
    }
  `);

  assert.ok(ast);
  assert.equal(ast.status, "completed");
  assert.equal(ast.findings.some((finding) => finding.ruleId === "ast:sql-input-sink"), false);
});

test("destructured route fields, loop elements, and object property writes preserve input flow", async () => {
  const ast = await scan(`
    function GET({ params, query }: any) {
      db.query("select * from users where id = " + params.id);
      for (const id of query.ids) db.query("select * from users where id = " + id);
      const holder: any = {};
      holder.id = query.id;
      db.query("select * from users where id = " + holder.id);
    }
  `);

  assert.ok(ast);
  const findings = ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink");
  assert.equal(findings.length, 3);
  assert.ok(findings.every((finding) => finding.confidence === "medium"));
});

test("React dangerouslySetInnerHTML and representative raw SQL APIs distinguish input from fixed arguments", async () => {
  const ast = await scan(`
    function Card({ params }: any) {
      return <section dangerouslySetInnerHTML={{ __html: params.html }} />;
    }
    function Queries(req: any) {
      prisma.$queryRawUnsafe(req.query.sql);
      db["query"](req.query.sql);
      prisma.$queryRawUnsafe("select 1");
    }
  `, "app.tsx");

  assert.ok(ast);
  assert.equal(ast.findings.filter((finding) => finding.ruleId === "ast:html-input-sink").length, 1);
  assert.equal(ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink").length, 2);
  assert.equal(ast.findings.some((finding) => finding.ruleId === "ast:sql-input-sink" && finding.location.line === 8), false);
});
