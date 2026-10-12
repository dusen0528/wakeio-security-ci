import { preflightApiPolicy, API_MAX_TIMEOUT_MS, type ApiPreflightResult } from './api.js';
import { preflightOpenApiPolicy, type OpenApiPolicyInput } from './openapi.js';
import { readJsonInput } from './json-input.js';
import { DEFAULT_TOOL_TIMEOUT_MS } from './source/process.js';

const USAGE = `Usage:
  wakeio-security-ci plan --api-policy FILE [--allow-private] [--timeout-ms N]
  wakeio-security-ci plan --openapi-input FILE [--allow-private] [--timeout-ms N]

Validate local JSON and print a redacted GET plan without DNS, HTTP or scan reports.
Use exactly one input. Timeout is 1..120000 ms (default: ${DEFAULT_TOOL_TIMEOUT_MS}, matching scan). Exit 0 means configuration ready;
exit 2 means blocked. Neither exit is a security result or permission to scan.
`;

function failure(code: string, location: string, message: string): ApiPreflightResult {
  const result = preflightApiPolicy({ policy: null });
  result.issues = [{ code, location, message }];
  return result;
}

/** Deliberately isolated from scan: no source/URL mode, report output or execution fallback. */
export async function planMain(argv: readonly string[]): Promise<number> {
  if (argv.length === 2 && ['--help', '-h'].includes(argv[1]!)) { process.stdout.write(USAGE); return 0; }
  let kind: '--api-policy' | '--openapi-input' | undefined, file: string | undefined;
  let allowPrivate = false, timeoutMs = DEFAULT_TOOL_TIMEOUT_MS, result: ApiPreflightResult;
  const seen = new Set<string>();
  try {
    for (let index = 1; index < argv.length; index++) {
      const [flag, ...assigned] = argv[index]!.split('=');
      if (!['--api-policy', '--openapi-input', '--allow-private', '--timeout-ms'].includes(flag!) || seen.has(flag!)) throw Error('usage');
      seen.add(flag!);
      if (flag === '--allow-private') {
        if (assigned.length) throw Error('usage');
        allowPrivate = true;
      } else {
        const value = assigned.length ? assigned.join('=') : argv[++index];
        if (!value || value.startsWith('-')) throw Error('usage');
        if (flag === '--timeout-ms') {
          if (!/^\d+$/.test(value)) throw Error('usage');
          timeoutMs = Number(value);
          if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > API_MAX_TIMEOUT_MS) throw Error('usage');
        } else {
          if (kind) throw Error('usage');
          kind = flag as "--api-policy" | "--openapi-input"; file = value;
        }
      }
    }
    if (!kind || !file) throw Error('usage');
  } catch {
    result = failure('invalid_arguments', 'arguments', 'Use plan with exactly one --api-policy or --openapi-input file; optional --allow-private and --timeout-ms (1..120000).');
    process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return 2;
  }
  try {
    const input = await readJsonInput(file, 1024 * 1024);
    result = kind === '--api-policy' ? preflightApiPolicy({ policy: input, allowPrivate, timeoutMs })
      : preflightOpenApiPolicy({ input: input as OpenApiPolicyInput, allowPrivate, timeoutMs });
  } catch {
    result = failure('invalid_input_file', 'input', 'Use a readable, stable regular JSON file no larger than 1 MiB; symlinks and non-file inputs are unsupported.');
  }
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  return result.status === 'ready' ? 0 : 2;
}
