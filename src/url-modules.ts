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
}

/**
 * Parse JavaScript as data to discover only static ES module declarations.
 * This function never loads, evaluates, or resolves a module. Dynamic and
 * computed imports are counted so the caller can state the collection limit.
 */
export function scanModuleReferences(text: string): ModuleReferenceScan {
  const source = ts.createSourceFile("remote-module.js", text, ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
  // `SourceFile` intentionally does not expose parser diagnostics in the
  // public TypeScript type. `transpileModule` performs the same bounded parse
  // without executing or resolving the fetched source and provides the
  // diagnostics needed to report an incomplete import graph.
  const parsed = ts.transpileModule(text, {
    fileName: "remote-module.js",
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
    reportDiagnostics: true,
  });
  const staticReferences: StaticModuleReference[] = [];
  let dynamicImports = 0;
  let computedImports = 0;

  const visit = (node: ts.Node): void => {
    if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
      staticReferences.push({ specifier: node.moduleSpecifier.text, kind: "import" });
    } else if (ts.isExportDeclaration(node) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      staticReferences.push({ specifier: node.moduleSpecifier.text, kind: "export" });
    } else if (ts.isImportEqualsDeclaration(node) && ts.isExternalModuleReference(node.moduleReference) && ts.isStringLiteral(node.moduleReference.expression)) {
      // TypeScript's `import x = require("./x")` is a static module edge,
      // even though it uses CommonJS resolution at runtime.
      staticReferences.push({ specifier: node.moduleReference.expression.text, kind: "import" });
    } else if (ts.isCallExpression(node) && node.expression.kind === ts.SyntaxKind.ImportKeyword) {
      dynamicImports += 1;
      const argument = node.arguments[0];
      if (!argument || !ts.isStringLiteral(argument)) computedImports += 1;
    }
    ts.forEachChild(node, visit);
  };
  visit(source);

  return {
    staticReferences,
    dynamicImports,
    computedImports,
    parseDiagnostics: parsed.diagnostics?.length ?? 0,
  };
}
