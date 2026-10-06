import test from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scanModuleReferences } from "../src/url-modules.js";

const execFileAsync = promisify(execFile);

test("module discovery preserves static declaration order and distinguishes dynamic imports", () => {
  const scan = scanModuleReferences(`import './one.js'; export { two } from './two.js';
    import three = require('./three.js'); import('./dynamic.js'); import(name);`);
  assert.deepEqual(scan.staticReferences, [
    { specifier: "./one.js", kind: "import" },
    { specifier: "./two.js", kind: "export" },
    { specifier: "./three.js", kind: "import" },
  ]);
  assert.equal(scan.dynamicImports, 2);
  assert.equal(scan.computedImports, 1);
  assert.equal(scan.parseDiagnostics, 0);
  assert.equal(scan.incompleteReason, undefined);
});

test("pinned parser syntax diagnostics are preserved without transpilation", () => {
  assert.equal(scanModuleReferences(`import './valid.js';`).parseDiagnostics, 0);
  assert.ok(scanModuleReferences(`import './valid.js'; const broken = ;`).parseDiagnostics > 0);
});

test("module traversal stays bounded on deep binary trees and handles parser stack failure", async () => {
  const moduleUrl = new URL("../src/url-modules.js", import.meta.url).href;
  const script = `import assert from 'node:assert/strict';
    import { scanModuleReferences } from ${JSON.stringify(moduleUrl)};
    const malformed = scanModuleReferences('import "./kept.js"; ' + 'a-'.repeat(40000));
    assert.deepEqual(malformed.staticReferences, [{ specifier: './kept.js', kind: 'import' }]);
    assert.ok(malformed.parseDiagnostics > 0);
    assert.equal(malformed.incompleteReason, undefined);
    const valid = scanModuleReferences('import "./kept.js"; ' + 'a-'.repeat(40000) + 'a;');
    assert.equal(valid.parseDiagnostics, 0);
    assert.equal(valid.incompleteReason, undefined);
    const nested = scanModuleReferences('('.repeat(40000) + 'x' + ')'.repeat(40000));
    assert.equal(nested.incompleteReason, 'parser_failure');
    const limited = scanModuleReferences('import "./kept.js"; ' + 'x;'.repeat(120000));
    assert.equal(limited.incompleteReason, 'ast_limit');
    assert.equal(limited.staticReferences[0].specifier, './kept.js');
    process.stdout.write('bounded');`;
  const { stdout } = await execFileAsync(process.execPath, ["--input-type=module", "-e", script], { timeout: 10_000, maxBuffer: 16_384 });
  assert.equal(stdout, "bounded");
});
