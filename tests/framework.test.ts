import test from "node:test";
import assert from "node:assert/strict";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { runSource } from "../src/source.js";
import { maskSql } from "../src/source/framework.js";

async function scratch(): Promise<string> {
  return mkdtemp(join(tmpdir(), "wakeio-security-ci-framework-"));
}

function frameworkFindings(checks: Awaited<ReturnType<typeof runSource>>) {
  return checks.find((check) => check.id === "source.framework");
}

test("Supabase rules ignore SQL comments and string literals but find explicit dangerous candidates", async () => {
  const root = await scratch();
  try {
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "001_init.sql"), [
      "-- ALTER TABLE public.comments DISABLE ROW LEVEL SECURITY;",
      "SELECT 'DISABLE ROW LEVEL SECURITY';",
      "/* CREATE POLICY fake ON public.comments TO PUBLIC USING (true); */",
      "ALTER TABLE public.comments DISABLE ROW LEVEL SECURITY;",
      "CREATE POLICY public_read ON public.comments FOR SELECT TO PUBLIC USING (true);",
      "-- an EOF line comment is complete SQL",
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    assert.equal(check?.status, "completed");
    assert.deepEqual(check?.findings.map((finding) => finding.ruleId), [
      "supabase:disable-row-level-security",
      "supabase:permissive-public-policy",
    ]);
    assert.equal(check?.findings[1]?.severity, "medium");
    assert.equal(check?.findings[1]?.confidence, "low");
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Supabase rules accept restrictive or role-bound policies and an RLS disable followed by enable", async () => {
  const root = await scratch();
  try {
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "002_safe.sql"), [
      "ALTER TABLE public.items DISABLE ROW LEVEL SECURITY;",
      "ALTER TABLE public.items ENABLE ROW LEVEL SECURITY;",
      "CREATE POLICY owner_read ON public.items AS PERMISSIVE FOR SELECT TO authenticated USING (auth.uid() = owner_id);",
      "CREATE POLICY restricted_public ON public.items AS RESTRICTIVE FOR SELECT TO PUBLIC USING (true);",
      "CREATE POLICY owner_write ON public.items FOR INSERT TO authenticated WITH CHECK (auth.uid() = owner_id);",
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    assert.equal(check?.status, "completed");
    assert.equal(check?.findings.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Next client rules find shaped server secrets while distinguishing role labels and public Supabase keys", async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, "Client.tsx"), [
      "\"use client\";",
      "const serverKey = \"sb_secret_SYNTHETIC_SERVER_KEY_12345\";",
      "const roleLabel = \"service_role\";",
      "const anon = \"sb_anon_SYNTHETIC_PUBLIC_KEY\";",
      "const publishable = \"sb_publishable_SYNTHETIC_PUBLIC_KEY\";",
      "const NEXT_PUBLIC_SUPABASE_ANON_KEY = anon;",
      "const NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY = publishable;",
      "const NEXT_PUBLIC_API_KEY = \"sb_anon_SYNTHETIC_PUBLIC_KEY\";",
      "const NEXT_PUBLIC_API_TOKEN = \"public-client-config\";",
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    assert.equal(check?.status, "completed");
    const findings = check?.findings ?? [];
    assert.ok(findings.some((finding) => finding.ruleId === "next:client-server-secret-literal" && finding.severity === "critical" && finding.confidence === "high"));
    assert.ok(findings.some((finding) => finding.ruleId === "next:public-server-secret-variable" && finding.severity === "medium" && finding.confidence === "low"));
    assert.equal(findings.filter((finding) => finding.ruleId === "next:client-server-secret-literal").length, 1);
    assert.equal(findings.filter((finding) => finding.ruleId === "next:public-server-secret-variable").length, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Next client rules recognize a decoded service-role JWT but not a role label", async () => {
  const root = await scratch();
  try {
    const payload = Buffer.from(JSON.stringify({ role: "service_role", ref: "synthetic" }), "utf8").toString("base64url");
    const jwt = `eyJhbGciOiJIUzI1NiJ9.${payload}.synthetic-signature`;
    await writeFile(join(root, "JwtClient.tsx"), [
      "\"use client\";",
      `const backendToken = "${jwt}";`,
      "const harmlessLabel = \"service_role\";",
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    const findings = check?.findings ?? [];
    assert.equal(check?.status, "completed");
    assert.deepEqual(findings.map((finding) => [finding.ruleId, finding.severity, finding.confidence]), [
      ["next:client-server-secret-literal", "critical", "high"],
    ]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Backend-only role labels and Supabase anon/publishable keys are not framework findings", async () => {
  const root = await scratch();
  try {
    await writeFile(join(root, "server.ts"), [
      "const SUPABASE_SERVICE_ROLE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY;",
      "const roleLabel = \"service_role\";",
      "const anon = \"sb_anon_SYNTHETIC_PUBLIC_KEY\";",
      "const publishable = \"sb_publishable_SYNTHETIC_PUBLIC_KEY\";",
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    assert.equal(check?.status, "not_applicable");
    assert.equal(check?.findings.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("PostgreSQL nested comments and E strings do not leak SQL keywords into migration findings", async () => {
  const root = await scratch();
  try {
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "003_comments.sql"), [
      "/* outer",
      " /* nested */",
      " ALTER TABLE public.fake DISABLE ROW LEVEL SECURITY;",
      "*/",
      "SELECT E'DISABLE ROW LEVEL SECURITY \\\' still inside';",
      "ALTER TABLE public.real DISABLE ROW LEVEL SECURITY;",
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    assert.equal(check?.status, "completed");
    assert.deepEqual(check?.findings.map((finding) => finding.ruleId), ["supabase:disable-row-level-security"]);
    assert.equal(maskSql("SELECT E'DISABLE ROW LEVEL SECURITY \\\' still inside';").complete, true);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Quoted table identity preserves case and dots when matching RLS enable operations", async () => {
  const root = await scratch();
  try {
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "004_quotes.sql"), [
      'ALTER TABLE "public"."users" DISABLE ROW LEVEL SECURITY;',
      'ALTER TABLE "public"."users" ENABLE ROW LEVEL SECURITY;',
      'ALTER TABLE "public"."Users" DISABLE ROW LEVEL SECURITY;',
      'ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;',
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    assert.equal(check?.status, "completed");
    assert.deepEqual(check?.findings.map((finding) => [finding.ruleId, finding.location.line]), [["supabase:disable-row-level-security", 3]]);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Quoted table identity preserves significant spaces and escaped quotes", async () => {
  const root = await scratch();
  try {
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "004b_quoted-spelling.sql"), [
      'ALTER TABLE "public"."my table " DISABLE ROW LEVEL SECURITY;',
      'ALTER TABLE "public"."my table " ENABLE ROW LEVEL SECURITY;',
      'ALTER TABLE "public"."a""b" DISABLE ROW LEVEL SECURITY;',
      'ALTER TABLE "public"."a""b" ENABLE ROW LEVEL SECURITY;',
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    assert.equal(check?.status, "completed");
    assert.equal(check?.findings.length, 0);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("CREATE plus row grant without an observed RLS enable is an uncertain candidate", async () => {
  const root = await scratch();
  try {
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "005_grants.sql"), [
      "CREATE TABLE public.profiles (id uuid);",
      "GRANT REFERENCES ON TABLE public.profiles TO anon;",
      "GRANT SELECT ON TABLE public.profiles TO anon;",
    ].join("\n"));
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    const candidate = check?.findings.find((finding) => finding.ruleId === "supabase:grant-without-observed-rls");
    assert.equal(check?.status, "completed");
    assert.ok(candidate);
    assert.equal(candidate?.severity, "medium");
    assert.equal(candidate?.confidence, "low");
    assert.equal(candidate?.location.line, 3);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Cross-migration CREATE and GRANT candidates report the grant file location", async () => {
  const root = await scratch();
  try {
    await mkdir(join(root, "supabase", "migrations"), { recursive: true });
    await writeFile(join(root, "supabase", "migrations", "006_create.sql"), "CREATE TABLE public.audit (id uuid);\n");
    await writeFile(join(root, "supabase", "migrations", "007_grant.sql"), "GRANT SELECT ON TABLE public.audit TO authenticated;\n");
    const check = frameworkFindings(await runSource({ root, tools: [] }));
    const candidate = check?.findings.find((finding) => finding.ruleId === "supabase:grant-without-observed-rls");
    assert.equal(check?.status, "completed");
    assert.equal(candidate?.location.path, "supabase/migrations/007_grant.sql");
    assert.equal(candidate?.location.line, 1);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Next client env references and relative re-exports are checked without exposing values", async () => {
  const root = await scratch();
  const secret = "sb_secret_SYNTHETIC_ENV_VALUE_12345";
  try {
    await writeFile(join(root, ".env.local"), [
      `NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=${secret}`,
      `SUPABASE_SERVICE_ROLE_KEY=${secret}`,
      "NEXT_PUBLIC_SUPABASE_ANON_KEY=sb_anon_SYNTHETIC_PUBLIC_KEY",
    ].join("\n"));
    await writeFile(join(root, "Client.tsx"), [
      '"use client";',
      'export { leaked } from "./server-values";',
      'export { imported } from "./server-env";',
      "const service = process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY;",
      "const anon = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;",
    ].join("\n"));
    await writeFile(join(root, "server-values.ts"), `export const leaked = "${secret}";\n`);
    await writeFile(join(root, "server-env.ts"), "export const imported = process.env.SUPABASE_SERVICE_ROLE_KEY;\n");
    const checks = await runSource({ root, tools: [] });
    const check = frameworkFindings(checks);
    const findings = check?.findings ?? [];
    assert.equal(check?.status, "completed");
    assert.ok(findings.some((finding) => finding.ruleId === "next:client-server-secret-env" && finding.severity === "critical"));
    assert.ok(findings.some((finding) => finding.ruleId === "next:client-server-secret-env" && finding.location.path === "server-env.ts"));
    assert.ok(findings.some((finding) => finding.ruleId === "next:client-server-secret-literal" && finding.location.path === "server-values.ts"));
    assert.equal(findings.some((finding) => finding.location.path === "Client.tsx" && finding.ruleId === "next:client-server-secret-env" && finding.location.line === 5), false);
    assert.equal(JSON.stringify(checks).includes(secret), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Shared client imports produce one finding and reachable syntax errors make coverage partial", async () => {
  const root = await scratch();
  const secret = "sb_secret_SYNTHETIC_SHARED_VALUE_12345";
  try {
    await writeFile(join(root, "ClientA.tsx"), ['"use client";', 'export { leaked } from "./shared";'].join("\n"));
    await writeFile(join(root, "ClientB.tsx"), ['"use client";', 'export { leaked } from "./shared";'].join("\n"));
    await writeFile(join(root, "shared.ts"), `export const leaked = "${secret}";\nexport const broken = {\n`);
    const checks = await runSource({ root, tools: [] });
    const check = frameworkFindings(checks);
    const findings = check?.findings ?? [];
    assert.equal(check?.status, "partial");
    assert.equal(findings.filter((finding) => finding.ruleId === "next:client-server-secret-literal").length, 1);
    assert.equal(JSON.stringify(checks).includes(secret), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Next config env object checks server values even when the exported key is not NEXT_PUBLIC", async () => {
  const root = await scratch();
  const secret = "sb_secret_SYNTHETIC_CONFIG_VALUE_12345";
  try {
    await writeFile(join(root, ".env"), `SUPABASE_SERVICE_ROLE_KEY=${secret}\n`);
    await writeFile(join(root, "next.config.js"), [
      "module.exports = {",
      "  env: {",
      "    SUPABASE_SERVICE_ROLE_KEY: process.env.SUPABASE_SERVICE_ROLE_KEY,",
      '    NEXT_PUBLIC_SUPABASE_ANON_KEY: "sb_anon_SYNTHETIC_PUBLIC_KEY",',
      "  },",
      "};",
    ].join("\n"));
    const checks = await runSource({ root, tools: [] });
    const check = frameworkFindings(checks);
    const candidate = check?.findings.find((finding) => finding.ruleId === "next:config-env-server-secret");
    assert.equal(check?.status, "completed");
    assert.equal(candidate?.severity, "critical");
    assert.equal(candidate?.location.path, "next.config.js");
    assert.equal(JSON.stringify(checks).includes(secret), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test("Next server-action modules stay behind the client boundary and React imports do not imply one", async () => {
  const root = await scratch();
  const secret = "sb_secret_SYNTHETIC_SERVER_ACTION_VALUE_12345";
  try {
    await writeFile(join(root, ".env"), `SUPABASE_SERVICE_ROLE_KEY=${secret}\n`);
    await writeFile(join(root, "Client.tsx"), [
      '"use client";',
      'import { save } from "./actions";',
      "export function Button() { return <button onClick={() => save()}>Save</button>; }",
    ].join("\n"));
    await writeFile(join(root, "actions.ts"), [
      '"use server";',
      "export async function save() {",
      "  const key = process.env.SUPABASE_SERVICE_ROLE_KEY;",
      "  return Boolean(key);",
      "}",
    ].join("\n"));
    await writeFile(join(root, "ServerComponent.tsx"), [
      'import React from "react";',
      'import { value } from "./server-values";',
      "export function ServerComponent() { return <span>{value}</span>; }",
    ].join("\n"));
    await writeFile(join(root, "server-values.ts"), `export const value = "${secret}";\n`);
    const checks = await runSource({ root, tools: [] });
    const check = frameworkFindings(checks);
    assert.equal(check?.status, "completed");
    assert.equal(check?.findings.some((finding) => finding.ruleId === "next:client-server-secret-env"), false);
    assert.equal(check?.findings.some((finding) => finding.ruleId === "next:client-server-secret-literal"), false);
    assert.equal(JSON.stringify(checks).includes(secret), false);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
