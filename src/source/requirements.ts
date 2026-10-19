interface RequirementsInspection {
  pinned: boolean;
  packageCount: number;
}

export function inspectRequirementsFile(text: string): RequirementsInspection {
  let packageCount = 0;
  let unresolved = false;
  for (const rawLine of text.replace(/^\uFEFF/, "").split(/\r\n|\r|\n/)) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line || line.startsWith("#")) continue;
    // Includes and constraints require resolver context outside this bounded
    // snapshot. Treating them as a complete lock would be a clean
    // result with unknown package coverage, so retain them as partial input.
    if (/^(?:-r|--requirement|-c|--constraint)(?:\s+|=)/i.test(line)) {
      unresolved = true;
      continue;
    }
    // A small set of pip options does not declare a package. Other options
    // (and editable/VCS/URL requirements) are deliberately unresolved.
    if (/^--(?:hash(?:=|\s)|require-hashes(?:=|\s|$)|index-url(?:=|\s)|extra-index-url(?:=|\s)|trusted-host(?:=|\s)|find-links(?:=|\s)|no-index(?:=|\s|$)|only-binary(?:=|\s)|no-binary(?:=|\s)|prefer-binary(?:=|\s)|pre(?:=|\s|$))/i.test(line)) continue;
    if (/^(?:-|git\+|hg\+|svn\+|bzr\+|https?:|file:|ssh:|\.?\.?\/|[A-Za-z0-9_.-]+\s*@\s*)/i.test(line)) {
      unresolved = true;
      continue;
    }
    // Keep markers and hash options out of the version check. A requirement
    // is lock-like only when its package specifier contains exactly ==.
    const withoutHash = line.split(/\s+--hash(?:=|\s+)/i, 1)[0].trim();
    const spec = withoutHash.split(";", 1)[0].trim();
    const match = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]\r\n]+\])?\s*==\s*([^\s,;#=]+)$/i.exec(spec);
    if (!match || (spec.match(/==/g)?.length ?? 0) !== 1 || /(?:[<>~!]=?|\*|,)/.test(spec.replace(/==/g, ""))) {
      unresolved = true;
      continue;
    }
    packageCount += 1;
  }
  return { pinned: !unresolved && packageCount > 0, packageCount };
}
