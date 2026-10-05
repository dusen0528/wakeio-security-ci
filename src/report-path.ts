// Internal artifact path/text safety; not exported by the root SDK.
import { posix } from 'node:path';

/** Redact common credential forms before any text reaches an artifact. */
export function redactSecrets(value: string): string {
  let result = value;

  // URL query strings are never needed in a report and frequently contain
  // tokens. This also strips credentials embedded in an URL authority.
  result = result.replace(/https?:\/\/[^\s<>"'`]+/gi, (candidate) => {
    const safe = safeHttpUrl(candidate);
    return safe ?? '[REDACTED_URL]';
  });

  // PEM bodies and common bearer/API-token forms.
  result = result.replace(
    /-----BEGIN [^-]+-----[\s\S]*?-----END [^-]+-----/gi,
    '[REDACTED_KEY]',
  );
  result = result.replace(
    /(authorization\s*[:=]\s*(?:bearer\s+)?|bearer\s+)([^\s,;]+)/gi,
    '$1[REDACTED]',
  );
  result = result.replace(
    /((?:api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret|session|cookie|refresh[_-]?token)\s*[:=]\s*)(["'])(?:\\.|(?!\2)[\s\S])*?\2/gi,
    '$1$2[REDACTED]$2',
  );
  result = result.replace(
    /\b[A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API[_-]?KEY|ACCESS[_-]?KEY)[A-Z0-9_-]*\s*=\s*(["'])(?:\\.|(?!\1)[\s\S])*?\1/gi,
    '[REDACTED_ASSIGNMENT]',
  );
  result = result.replace(
    /((?:api[_-]?key|access[_-]?key|secret|token|password|passwd|client[_-]?secret|session|cookie|refresh[_-]?token)\s*[:=]\s*["']?)([^\s"',;]+)/gi,
    '$1[REDACTED]',
  );
  result = result.replace(/\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]+\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bgithub_pat_[A-Za-z0-9_]+\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bxox[baprs]-[A-Za-z0-9-]+\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bAKIA[0-9A-Z]{16}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bASIA[0-9A-Z]{16}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{12,}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bAIza[0-9A-Za-z_-]{20,}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, '[REDACTED_TOKEN]');
  result = result.replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/g, '[REDACTED_JWT]');

  return result;
}

export function safeRelativePath(value: string): string | undefined {
  let path = value.replaceAll('\\', '/').trim();
  if (!path || path.includes('\u0000') || /[\u0000-\u001f\u007f]/.test(path)) {
    return undefined;
  }
  // Reject both absolute and drive-relative Windows spellings. A value such
  // as `C:report.txt` is not an absolute filesystem path on Windows, but it is
  // still interpreted as a URI scheme by some SARIF consumers.
  if (path.startsWith('/') || path.startsWith('//') || /^[A-Za-z]:/.test(path)) {
    return undefined;
  }

  const parts = path.split('/');
  const safeParts: string[] = [];
  for (const part of parts) {
    if (!part || part === '.') continue;
    if (part === '..') {
      if (safeParts.length === 0) return undefined;
      safeParts.pop();
      continue;
    }
    safeParts.push(part);
  }
  path = posix.normalize(safeParts.join('/'));
  if (!path || path === '..' || path.startsWith('../') || path.startsWith('/')) {
    return undefined;
  }
  return path;
}

export function safeHttpUrl(value: unknown): string | undefined {
  if (typeof value !== 'string' || value.length === 0) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined;
    url.username = '';
    url.password = '';
    url.search = '';
    url.hash = '';
    return url.toString();
  } catch {
    return undefined;
  }
}

