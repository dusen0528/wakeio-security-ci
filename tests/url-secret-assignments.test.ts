import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scanSecretAssignments } from "../src/url-secret-assignments.js";

const execFileAsync = promisify(execFile);
const value = "synthetic_assignment_value";

test("secret assignments retain supported names, prefixes, delimiters and exact spans", () => {
  const keys = [
    "apiKey", "api_key", "api-key", "secret", "secretKey", "secret_key", "secret-key",
    "serviceRole", "service_role", "service-role", "serviceRoleKey", "service_role_key", "service-role-key",
    "accessKey", "access_key", "access-key", "accessToken", "access_token", "access-token",
    "auth", "authorization", "password", "passwd", "privateKey", "private_key", "private-key",
    "clientSecret", "client_secret", "client-secret", "sessionToken", "session_token", "session-token",
  ];
  for (const key of keys) {
    for (const prefix of ["", "APP_", "site-prod-", "ABC123_"]) {
      for (const delimiter of [" = ", "\" : ", "'\t:\n"]) {
        const span = `${prefix}${key.toUpperCase()}${delimiter}"${value}"`;
        const matches = [...scanSecretAssignments(`!${span};`)];
        assert.deepEqual(matches, [{ 0: span, index: 1 }]);
      }
    }
  }
});

test("secret assignments preserve word boundaries and non-overlapping literal matches", () => {
  const cases: [string, string | undefined][] = [
    [`_password="${value}"`, undefined],
    [`password_="${value}"`, undefined],
    [`notpassword="${value}"`, undefined],
    [`passwordSuffix="${value}"`, undefined],
    [`foo__password="${value}"`, undefined],
    [`foo--password="${value}"`, `password="${value}"`],
    [`_client-secret="${value}"`, `secret="${value}"`],
    [`_foo-api_key="${value}"`, `api_key="${value}"`],
    [`foo__bar-password="${value}"`, `password="${value}"`],
    [`foo_-password="${value}"`, `password="${value}"`],
    [`password = process.env.SECRET`, undefined],
    [`password = config.value`, undefined],
    [`password = "short"`, undefined],
    [`password = "unterminated`, undefined],
    [`password = "line\nbreak_value"`, undefined],
    [`password = "line\rbreak_value"`, undefined],
    [`password = 123456789012345`, undefined],
    [`password = 1234567890123456`, "password = 1234567890123456"],
    [`password = '12345678'`, "password = '12345678'"],
    [`password = "12345678"`, 'password = "12345678"'],
    [`password = 'api_key = "${value}"'`, `password = 'api_key = "${value}"'`],
  ];
  for (const [input, expected] of cases) {
    const matches = [...scanSecretAssignments(input)];
    assert.deepEqual(matches.map((match) => match[0]), expected === undefined ? [] : [expected], input);
    if (expected !== undefined) assert.equal(matches[0].index, input.indexOf(expected));
  }
});

test("bounded hostile URL text and whitespace finish under an independent process guard", async () => {
  // The parent process can terminate a regression even if a synchronous
  // matcher blocks the scan's own timer. Keep the hostile body at only 80KB;
  // the original matcher took over five seconds on this exact no-match case.
  const script = `
    import assert from "node:assert/strict";
    import { createServer } from "node:http";
    import { runUrl } from ${JSON.stringify(new URL("../src/url.js", import.meta.url).href)};
    import { scanSecretAssignments } from ${JSON.stringify(new URL("../src/url-secret-assignments.js", import.meta.url).href)};
    const body = "a-".repeat(40_000);
    const server = createServer((_request, response) => {
      response.setHeader("content-type", "text/html");
      response.end(body);
    });
    await new Promise(resolve => server.listen(0, "127.0.0.1", resolve));
    try {
      const started = performance.now();
      const checks = await runUrl({ url: "http://127.0.0.1:" + server.address().port, allowPrivate: true, timeoutMs: 100 });
      assert.equal(checks[0].findings.some(finding => finding.ruleId.startsWith("url.secret-")), false);
      assert.ok(["completed", "partial"].includes(checks[0].status));
      for (const input of [body, "password" + " ".repeat(80_000) + "!", 'password = "' + "a".repeat(80_000)]) {
        assert.equal([...scanSecretAssignments(input)].length, 0);
      }
      const positive = body + 'password = "synthetic_long_name_value"';
      const matches = [...scanSecretAssignments(positive)];
      assert.equal(matches.length, 1);
      assert.equal(matches[0].index, 0);
      console.log(JSON.stringify({ elapsedMs: performance.now() - started }));
    } finally {
      server.closeAllConnections();
      await new Promise(resolve => server.close(resolve));
    }
  `;
  const { stdout } = await execFileAsync(process.execPath, ["--input-type=module", "-e", script], { timeout: 4_000, maxBuffer: 16_384 });
  const measured = JSON.parse(stdout) as { elapsedMs: number };
  // This generous ceiling is a regression guard, not a claim that arbitrary
  // synchronous HTML/JS parsing can be preempted at the requested timeout.
  assert.ok(measured.elapsedMs < 2_000, `bounded URL fixture took ${measured.elapsedMs}ms`);
});
