import * as ts from "typescript";

export interface StaticModuleReference {
  specifier: string;
  kind: "import" | "export";
}

export interface ModuleReferenceScan {
  staticReferences: StaticModuleReference[];
  dynamicImports: number;
  computedImports: number;
  parseDiagnostics: number;
  incompleteReason?: "parser_failure" | "ast_limit";
}

// Network bodies are already bounded. Also cap the amount of AST work and
// pending traversal state so small but node-dense input stays bounded.
const MAX_MODULE_AST_NODES = 200_000;
const MAX_MODULE_TEXT_LENGTH = 2 * 1024 * 1024;

/**
 * Parse JavaScript as data to discover only static ES module declarations.
 * This function never loads, evaluates, or resolves a module. Dynamic and
 * computed imports are counted so the caller can state the collection limit.
 */
export function scanModuleReferences(text: string): ModuleReferenceScan {
  const result: ModuleReferenceScan = { staticReferences: [], dynamicImports: 0, computedImports: 0, parseDiagnostics: 0 };
  if (text.length > MAX_MODULE_TEXT_LENGTH) return { ...result, incompleteReason: "ast_limit" };
  try {
    // Parent links and transpilation both add unnecessary recursive passes.
    // The pinned TypeScript 5.9 parser supplies parseDiagnostics on SourceFile;
    // validate that internal field rather than executing the emitter merely
    // to read diagnostics. Missing diagnostics must not look like a clean parse.
    const source = ts.createSourceFile("remote-module.js", text, ts.ScriptTarget.Latest, false, ts.ScriptKind.JS);
    const diagnostics: unknown = (source as ts.SourceFile & { parseDiagnostics?: unknown }).parseDiagnostics;
    result.parseDiagnostics = Array.isArray(diagnostics) ? diagnostics.length : 1;
    const pending: ts.Node[] = [source];
    let scheduled = 1;
    while (pending.length > 0) {
      const node = pending.pop()!;

      if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
        result.staticReferences.push({ specifier: node.moduleSpecifier.text, kind: "import" });
      } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
        result.staticReferences.push({ specifier: node.moduleSpecifier.text, kind: "export" });
      } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference) && ts.isStringLiteral(node.moduleReference.expression)) {
        // TypeScript's `import x = require("./x")` is a static module edge,
        // even though it uses CommonJS resolution at runtime.
        result.staticReferences.push({ specifier: node.moduleReference.expression.text, kind: "import" });
      } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
        result.dynamicImports += 1;
        const argument = node.arguments[0];
        if (!argument || !ts.isStringLiteral(argument)) result.computedImports += 1;
      }
      const children: ts.Node[] = [];
      ts.forEachChild(node, (child) => {
        if (scheduled >= MAX_MODULE_AST_NODES) {
          result.incompleteReason = "ast_limit";
          return true;
        }
        scheduled += 1;
        children.push(child);
        return undefined;
      });
      // Preserve source order without recursive descent or spread arguments.
      for (let index = children.length - 1; index >= 0; index -= 1) pending.push(children[index]);
    }
  } catch {
    // The parser itself can exhaust its stack on deeply nested syntax. Keep
    // any references already found, and let the caller retain other findings.
    result.incompleteReason = "parser_failure";
  }
  return result;
}
