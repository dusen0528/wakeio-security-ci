import assert from 'node:assert/strict';
import test from 'node:test';
import { RelayStartupData, startupBudgetRecord } from '../src/runtime/runtimes/provision-relay-startup.js';

test('startup DATA accepts every two-chunk marker split in the original protocol order', () => {
  const startup = Buffer.from('WAKEIO_STARTUP_1\n'), ready = Buffer.from('RELAY_READY\n');
  for (let first = 0; first <= startup.length; first++) {
    for (let second = 0; second <= ready.length; second++) {
      const data = new RelayStartupData(), events: string[] = [];
      for (const chunk of [startup.subarray(0, first), startup.subarray(first),
        ready.subarray(0, second), ready.subarray(second)]) {
        const event = data.push(chunk);
        if (event !== undefined) events.push(event);
      }
      assert.deepEqual(events, ['startup', 'ready']);
      assert.doesNotThrow(() => data.finish());
    }
  }
});

test('startup DATA accepts single-byte chunks without granting readiness for a partial marker', () => {
  const data = new RelayStartupData(), events: (string | undefined)[] = [];
  for (const byte of Buffer.from('WAKEIO_STARTUP_1\nRELAY_READY\n')) {
    events.push(data.push(Buffer.from([byte])));
  }
  assert.deepEqual(events, [
    ...Array<undefined>(16).fill(undefined), 'startup',
    ...Array<undefined>(11).fill(undefined), 'ready',
  ]);
  assert.doesNotThrow(() => data.finish());
});

test('startup DATA refuses reordered duplicate non-ASCII overflowing and trailing protocol bytes', () => {
  const cases = [
    { before: [], invalid: Buffer.from('RELAY_READY\n') },
    { before: [], invalid: Buffer.from('WAKEIO_STARTUP_2\n') },
    { before: [], invalid: Buffer.from('WAKEIO_STARTUP_1\r\n') },
    { before: [], invalid: Buffer.from('WAKEIO_STARTUP_1\nRELAY_READY\n') },
    { before: [], invalid: Buffer.alloc(129, 65) },
    { before: [], invalid: Buffer.from([0x80]) },
    { before: ['WAKEIO_STARTUP_'], invalid: Buffer.from([0xb1, 10]) },
    { before: ['WAKEIO_STARTUP_1\n'], invalid: Buffer.from('WAKEIO_STARTUP_1\n') },
    { before: ['WAKEIO_STARTUP_1\n'], invalid: Buffer.from('RELAY_READY\nx') },
    { before: ['WAKEIO_STARTUP_1\n', 'RELAY_READY\n'], invalid: Buffer.from('RELAY_READY\n') },
    { before: ['WAKEIO_STARTUP_1\n', 'RELAY_READY\n'], invalid: Buffer.from([0]) },
    { before: ['WAKEIO_STARTUP_1\n', 'RELAY_READY\n'], invalid: Buffer.from('\n') },
  ];
  for (const row of cases) {
    const data = new RelayStartupData();
    for (const prefix of row.before) data.push(Buffer.from(prefix));
    assert.throws(() => data.push(row.invalid), { code: 'relay_startup_data' });
    assert.throws(() => data.finish(), { code: 'relay_startup_data' });
  }
});

test('startup DATA refuses EOF at every incomplete marker position', () => {
  const startup = Buffer.from('WAKEIO_STARTUP_1\n'), ready = Buffer.from('RELAY_READY\n');
  for (let offset = 0; offset < startup.length; offset++) {
    const data = new RelayStartupData();
    data.push(startup.subarray(0, offset));
    assert.throws(() => data.finish(), { code: 'relay_startup_data' });
  }
  for (let offset = 0; offset < ready.length; offset++) {
    const data = new RelayStartupData();
    data.push(startup);
    data.push(ready.subarray(0, offset));
    assert.throws(() => data.finish(), { code: 'relay_startup_data' });
  }
});

test('startup DATA retains its first failure and cannot resume after malformed input or EOF', () => {
  for (const truncate of [false, true]) {
    const data = new RelayStartupData();
    let failure: unknown;
    try {
      if (truncate) data.finish();
      else data.push(Buffer.from('X'));
    } catch (error) {
      if (!(error instanceof Error)) throw error;
      failure = error;
    }
    assert.ok(failure instanceof Error);
    assert.throws(() => data.push(Buffer.from('WAKEIO_STARTUP_1\n')), error => error === failure);
    assert.throws(() => data.finish(), error => error === failure);
  }
});

test('startup budget serializes only the bounded original integer allowance and version with ASCII LF', () => {
  for (const row of [
    { remaining: 1, expected: '{"v":1,"remainingMs":1}\n' },
    { remaining: 1729, expected: '{"v":1,"remainingMs":1729}\n' },
    { remaining: 900000, expected: '{"v":1,"remainingMs":900000}\n' },
  ]) {
    const record = startupBudgetRecord(row.remaining);
    const parsed: unknown = JSON.parse(record);
    assert.equal(record, row.expected);
    assert.deepEqual(parsed, { v: 1, remainingMs: row.remaining });
    assert.ok(Buffer.byteLength(record) <= 128);
  }
});

test('startup budget refuses expired excessive fractional and non-finite allowances', () => {
  for (const remaining of [0, -1, 900001, 0.5, 899999.5, NaN, Infinity, -Infinity, Number.MAX_SAFE_INTEGER]) {
    assert.throws(() => startupBudgetRecord(remaining), { code: 'relay_startup_budget' });
  }
});
