import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { collectSource } from '../src/source/collector.js';

test('Python dependency environments, intent state and comparison artifacts do not consume source scope', async () => {
  const root = await mkdtemp(join(tmpdir(), 'wakeio-python-collection-'));
  try {
    for (const name of ['.venv', 'venv', '__pycache__', '.intent-review']) {
      await mkdir(join(root, name));
      await writeFile(join(root, name, 'private.py'), 'TOKEN="local_state_should_not_be_scanned"');
    }
    await writeFile(join(root, 'comparison.json'), '{"token":"private_comparison_material"}');
    await writeFile(join(root, '.bandit'), '[bandit]\nexclude: app.py');
    await writeFile(join(root, 'app.py'), 'print("target source")');
    const snapshot = await collectSource({ root, maxFiles: 1 });
    assert.equal(snapshot.complete, true);
    assert.deepEqual(snapshot.files.map((file) => file.path), ['app.py']);
    assert.equal(JSON.stringify(snapshot).includes('local_state_should_not_be_scanned'), false);
  } finally { await rm(root, { recursive: true, force: true }); }
});
