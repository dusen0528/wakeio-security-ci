import { parseDastPolicy, prepareDastPolicy, snapshotDastEnvironment, dastProfileRevision, dastDefaultMaxRequests, dastRequestPlan, DAST_MAX_REQUESTS } from './dast.js';
import { normalizeUrl, validateStaticTarget } from './url-network.js';
import { preflightApiPolicy, API_MAX_TIMEOUT_MS, type ApiPreflightResult } from './api.js';
import { preflightOpenApiPolicy, type OpenApiPolicyInput } from './openapi.js';
import { readJsonInput } from './json-input.js';
import { DEFAULT_TOOL_TIMEOUT_MS } from './source/process.js';

const USAGE = `Usage:
  wakeio-security-ci plan --api-policy FILE [--allow-private] [--timeout-ms N]
  wakeio-security-ci plan --openapi-input FILE [--allow-private] [--timeout-ms N]
  wakeio-security-ci plan --dast-policy FILE [--dast-max-requests N] [--allow-private] [--timeout-ms N]

Validate local JSON and print a redacted fixed request plan without DNS, HTTP or scan reports.
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
  let kind: '--api-policy' | '--openapi-input' | '--dast-policy' | undefined, file: string | undefined;
  let allowPrivate = false, timeoutMs = DEFAULT_TOOL_TIMEOUT_MS, maxRequests: number | undefined, result: ApiPreflightResult;
  const seen = new Set<string>();
  try {
    for (let index = 1; index < argv.length; index++) {
      const [flag, ...assigned] = argv[index]!.split('=');
      if (!['--api-policy', '--openapi-input', '--dast-policy', '--dast-max-requests', '--allow-private', '--timeout-ms'].includes(flag!) || seen.has(flag!)) throw Error('usage');
      seen.add(flag!);
      if (flag === '--allow-private') {
        if (assigned.length) throw Error('usage');
        allowPrivate = true;
      } else {
        const value = assigned.length ? assigned.join('=') : argv[++index];
        if (!value || value.startsWith('-')) throw Error('usage');
        if (flag === '--dast-max-requests') {
          if (!/^\d+$/.test(value)) throw Error('usage');
          maxRequests = Number(value);
          if (!Number.isSafeInteger(maxRequests) || maxRequests < 1 || maxRequests > DAST_MAX_REQUESTS) throw Error('usage');
        } else if (flag === '--timeout-ms') {
          if (!/^\d+$/.test(value)) throw Error('usage');
          timeoutMs = Number(value);
          if (!Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > API_MAX_TIMEOUT_MS) throw Error('usage');
        } else {
          if (kind) throw Error('usage');
          kind = flag as '--api-policy' | '--openapi-input' | '--dast-policy'; file = value;
        }
      }
    }
    if (!kind || !file || seen.has('--dast-max-requests') && kind !== '--dast-policy') throw Error('usage');
  } catch {
    result = failure('invalid_arguments', 'arguments', 'Use plan with exactly one --api-policy, --openapi-input or --dast-policy file; optional --allow-private and --timeout-ms (1..120000).');
    process.stdout.write(JSON.stringify(result, null, 2) + '\n'); return 2;
  }
  try {
    const input = await readJsonInput(file, 1024 * 1024);
    if (kind === '--dast-policy') {
      const parsed = parseDastPolicy(input);
      const { policy, policySha256 } = prepareDastPolicy(parsed.policy, { allowPrivate, env: snapshotDastEnvironment(parsed.policy) });
      validateStaticTarget(normalizeUrl(policy.url), allowPrivate);
      const plannedRequests = dastDefaultMaxRequests(policy);
      const effectiveMaxRequests = maxRequests ?? plannedRequests;
      if (effectiveMaxRequests < plannedRequests) {
        result = failure('insufficient_request_budget', 'dast-max-requests', 'The selected fixed native DAST plan exceeds the HTTP attempt budget; no requests were made.');
        process.stdout.write(JSON.stringify(result, null, 2) + '\n');
        return 2;
      }
      process.stdout.write(JSON.stringify({ version: 1, kind: 'native-dast-plan', status: 'ready',
        origin: new URL(policy.baseUrl).origin, policySha256, profileRevision: dastProfileRevision(policy),
        plannedRequests, maxHttpAttempts: effectiveMaxRequests, timeoutMs, allowPrivate,
        ...(policy.version === 4 ? { method: policy.method } : {}),
        // Preserve the historical v1 envelope; newer profiles share the core
        // enum-only plan without request URLs or assertion values.
        ...(policy.version === 1 ? {} : { steps: dastRequestPlan(policy).map(({ ordinal, phase }) => ({ ordinal, phase })) }),
        notes: ['Configuration only; explicit active consent is still required to scan. No DNS lookup or request was made.'],
      }, null, 2) + '\n');
      return 0;
    }
    result = kind === '--api-policy' ? preflightApiPolicy({ policy: input, allowPrivate, timeoutMs })
      : preflightOpenApiPolicy({ input: input as OpenApiPolicyInput, allowPrivate, timeoutMs });
  } catch {
    result = failure('invalid_input_file', 'input', 'Use a readable, stable regular JSON file no larger than 1 MiB; symlinks and non-file inputs are unsupported.');
  }
  process.stdout.write(JSON.stringify(result, null, 2) + '\n');
  return result.status === 'ready' ? 0 : 2;
}
