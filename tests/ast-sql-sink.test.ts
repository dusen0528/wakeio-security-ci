import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSource } from "../src/source.js";

async function scan(source: string, fileName = "app.ts") {
  const root = await mkdtemp(join(tmpdir(), "wakeio-security-ci-ast-sink-"));
  try {
    await writeFile(join(root, fileName), source);
    const checks = await runSource({ root, tools: [] });
    return checks.find((check) => check.id === "source.builtin-ast");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

test("a proven local URLSearchParams serializer named query is excluded without hiding a database query", async () => {
  const ast = await scan(`
    function query(params: Record<string, string | number | undefined>) {
      const search = new URLSearchParams();
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined) search.set(key, String(value));
      });
      return search.toString();
    }
    function load(params: Record<string, string>, req: any) {
      query(params);
      db.query("select " + req.query.id);
    }
  `);

  assert.ok(ast);
  const findings = ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink");
  assert.equal(findings.length, 1);
  assert.equal(findings[0]?.location.line, 11);
});

test("an unproven bare query call remains a SQL candidate", async () => {
  const ast = await scan(`
    function load(req: any) {
      query(req.query.sql);
    }
  `);

  assert.ok(ast);
  assert.equal(ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink").length, 1);
});

test("a shadowed query parameter is not treated as the top-level serializer", async () => {
  const ast = await scan(`
    function query(params: Record<string, string | number | undefined>) {
      const search = new URLSearchParams();
      return search.toString() + String(params.page ?? "");
    }
    function load(query: any, req: any) {
      query(req.query.sql);
    }
  `);

  assert.ok(ast);
  assert.equal(ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink").length, 1);
});

test("a reassigned top-level query binding is not exempted", async () => {
  const ast = await scan(`
    function query(params: Record<string, string | number | undefined>) {
      const search = new URLSearchParams();
      return search.toString() + String(params.page ?? "");
    }
    function load(req: any) {
      query = replacement;
      query(req.query.sql);
    }
  `);

  assert.ok(ast);
  assert.equal(ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink").length, 1);
});

test("an unknown call or SQL call in the serializer body disables the exemption", async () => {
  const ast = await scan(`
    function query(params: Record<string, string | number | undefined>) {
      const search = new URLSearchParams();
      db.query(params);
      save(search);
      return search.toString();
    }
    function load(params: Record<string, string>) {
      query(params);
    }
  `);

  assert.ok(ast);
  assert.equal(ast.findings.filter((finding) => finding.ruleId === "ast:sql-input-sink").length, 2);
});

test("shadowed serializer builtins and reassigned locals remain candidates", async () => {
  for (const extra of ["const URLSearchParams = replacement;", "const String = replacement;", "const Object = replacement;"]) {
    const ast = await scan(`
      ${extra}
      function query(params: any) {
        const search = new URLSearchParams();
        return search.toString();
      }
      function load(req: any) { query(req.query.sql); }
    `);
    assert.equal(ast?.findings.filter((f) => f.ruleId === "ast:sql-input-sink").length, 1, extra);
  }
  const ast = await scan(`
    function query(params: any) {
      let search = new URLSearchParams();
      search = database;
      return search.toString();
    }
    function load(req: any) { query(req.query.sql); }
  `);
  assert.equal(ast?.findings.filter((f) => f.ruleId === "ast:sql-input-sink").length, 1);
});

test("a nested URLSearchParams binding cannot bless an outer or shadowed receiver", async () => {
  for (const body of [
    '{ const search = new URLSearchParams(); } search.set("sql", params); return search.toString();',
    'const search = new URLSearchParams(); { const search = database; search.set("sql", params); } return search.toString();',
  ]) {
    const ast = await scan(`
      const search = database;
      function query(params: any) { ${body} }
      function load(req: any) { query(req.query.sql); }
    `);
    assert.equal(ast?.findings.filter((f) => f.ruleId === "ast:sql-input-sink").length, 1, body);
  }
});

test("TypeScript runtime builtin bindings disable the serializer exception", async () => {
  for (const binding of ['namespace Object {}', 'import Object = require("unsafe");', 'enum String { value }']) {
    const ast = await scan(`
      ${binding}
      function query(params: any) {
        const search = new URLSearchParams();
        Object.entries(params).forEach(([key, value]) => search.set(key, String(value)));
        return search.toString();
      }
      function load(req: any) { query(req.query.sql); }
    `);
    assert.equal(ast?.findings.filter((f) => f.ruleId === "ast:sql-input-sink").length, 1, binding);
  }
});
