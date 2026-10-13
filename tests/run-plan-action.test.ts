// The Action wrapper is checked-in JavaScript, so keep its owned process probes
// in the same language and include them in the ordinary compiled test suite.
import { fileURLToPath } from 'node:url';
await import(fileURLToPath(new URL('../../tests/run-plan-action.test.mjs', import.meta.url)));
