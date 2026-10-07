import test from 'node:test';
import assert from 'node:assert/strict';
import { lstat, mkdtemp, open, readFile, rm, symlink, writeFile, rename } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runBounded } from './ci-process.mjs';
import { NUCLEI_TEMPLATES, verifyTemplateArchive, validateTemplateEntries, requiredNucleiEnvironment, readLocalTemplateArchive } from './bootstrap-nuclei.mjs';

const prefix = `nuclei-templates-${NUCLEI_TEMPLATES.commit}`;
const entries = ['http/misconfiguration/', 'http/exposures/', 'LICENSE.md', 'templates-checksum.txt'].map(path => prefix + '/' + path).join('\n');
const setup = { engine: { version: '3.11.1', path: '/prepared/nuclei' }, templates: { ...NUCLEI_TEMPLATES, path: '/prepared/templates' } };

test('Nuclei setup fixes an immutable official template source and rejects unverified bytes', () => {
  assert.match(NUCLEI_TEMPLATES.commit, /^[a-f0-9]{40}$/);
  assert.equal(NUCLEI_TEMPLATES.url, `https://codeload.github.com/projectdiscovery/nuclei-templates/tar.gz/${NUCLEI_TEMPLATES.commit}`);
  assert.throws(() => verifyTemplateArchive(Buffer.from('tampered')), /checksum/);
  assert.throws(() => verifyTemplateArchive(Buffer.alloc(0)), /size/);
  assert.throws(() => verifyTemplateArchive(Buffer.alloc(16 * 1024 * 1024 + 1)), /size/);
});

test('template extraction preserves both full scopes and license but refuses unsafe archive entries', () => {
  assert.doesNotThrow(() => validateTemplateEntries(entries, 'drwx scope\n-rw- license'));
  for (const entry of ['/absolute', '../outside', `${prefix}/../outside`, `${prefix}/a/../../outside`, `${prefix}evil/scope`, `${prefix}/a\\b`]) {
    assert.throws(() => validateTemplateEntries(entries + '\n' + entry, '-rw file'), /path/);
  }
  for (const type of ['lrwx link -> outside', 'hrw hardlink', 'crw device']) {
    assert.throws(() => validateTemplateEntries(entries, type), /type/);
  }
  assert.throws(() => validateTemplateEntries(entries.replace(`${prefix}/http/exposures/`, ''), '-rw file'), /required_entry|path/);
});

test('required-engine environment never silently opts out of real Nuclei tests', () => {
  assert.deepEqual(requiredNucleiEnvironment({}, setup), {
    WAKEIO_NUCLEI: '/prepared/nuclei', WAKEIO_NUCLEI_TEMPLATES: '/prepared/templates', WAKEIO_REQUIRE_NUCLEI: '1',
  });
  assert.throws(() => requiredNucleiEnvironment({}, undefined), /missing_or_unpinned/);
  assert.throws(() => requiredNucleiEnvironment({}, { ...setup, templates: { ...setup.templates, commit: 'main' } }), /missing_or_unpinned/);
  assert.throws(() => requiredNucleiEnvironment({}, { ...setup, engine: { version: 'old' } }), /missing_or_unpinned/);
  assert.throws(() => requiredNucleiEnvironment({ WAKEIO_NUCLEI: 'path\nINJECT=1', WAKEIO_NUCLEI_TEMPLATES: '/templates' }), /paths_required/);
  const explicit = requiredNucleiEnvironment({ WAKEIO_NUCLEI: '/explicit/nuclei', WAKEIO_NUCLEI_TEMPLATES: '/explicit/templates', WAKEIO_REQUIRE_NUCLEI: '0' });
  assert.equal(explicit.WAKEIO_NUCLEI, '/explicit/nuclei'); assert.equal(explicit.WAKEIO_REQUIRE_NUCLEI, '1');
});

test('self-test provisions pinned Nuclei before the unchanged zero-skip required-engine gate', async () => {
  const workflow = await readFile(new URL('../.github/workflows/self-test.yml', import.meta.url), 'utf8');
  const suite = await readFile(new URL('./test-schemathesis.mjs', import.meta.url), 'utf8');
  const prepare = workflow.indexOf('node scripts/bootstrap-nuclei.mjs');
  assert.ok(prepare >= 0);
  assert.ok(prepare < workflow.indexOf('npm run test:schemathesis'));
  assert.ok(workflow.includes('scripts/bootstrap-nuclei.test.mjs'));
  for (const name of ['real nuclei: risk/normal pair, wire coverage and egress refusal counts',
    'real nuclei: request budget and a failing target are partial even though nuclei exits 0']) assert.ok(suite.includes(name));
  assert.ok(suite.includes("join(root, 'build/tests/nuclei.test.js')"));
  assert.ok(suite.includes('requiredNucleiEnvironment'));
});


test('local template override bounds allocation and refuses symlinks, directories, empty and oversized files', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-nuclei-archive-'));
  try {
    const file = join(directory, 'archive'), link = join(directory, 'link'), huge = join(directory, 'huge');
    await writeFile(file, 'bounded input');
    assert.equal((await readLocalTemplateArchive(file)).toString(), 'bounded input');
    await symlink(file, link);
    const sparse = await open(huge, 'wx');
    try { await sparse.truncate(2 * 1024 * 1024 * 1024); } finally { await sparse.close(); }
    await writeFile(join(directory, 'empty'), '');
    for (const input of [link, directory, huge, join(directory, 'empty')]) {
      await assert.rejects(readLocalTemplateArchive(input), /type_or_size/);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('local template override refuses a FIFO without opening or waiting for a writer', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-nuclei-fifo-'));
  try {
    const fifo = join(directory, 'archive');
    const made = await runBounded('mkfifo', [fifo], { timeoutMs: 1000 });
    assert.equal(made.exitCode, 0);
    let opened = false;
    await assert.rejects(readLocalTemplateArchive(fifo, { lstat, open() { opened = true; throw Error('must_not_open'); } }), /type_or_size/);
    assert.equal(opened, false);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('local template override rejects path replacement and content/size changes during bounded reads', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'wakeio-nuclei-race-'));
  try {
    const file = join(directory, 'archive');
    for (const mutation of ['replace-before-open', 'symlink-before-open', 'fifo-before-open', 'replace-during-read', 'grow', 'shrink', 'same-size']) {
      await rm(file, { force: true }); await writeFile(file, 'original input');
      let changed = false, closed = false;
      const operations = { lstat, async open(path, flags) {
        if (mutation.endsWith('before-open')) {
          await rename(file, join(directory, 'previous'));
          if (mutation === 'symlink-before-open') await symlink(join(directory, 'previous'), file);
          else if (mutation === 'fifo-before-open') assert.equal((await runBounded('mkfifo', [file], { timeoutMs: 1000 })).exitCode, 0);
          else await writeFile(file, 'original input');
        }
        const handle = await open(path, flags);
        return { stat: (...args) => handle.stat(...args), close: async () => { closed = true; await handle.close(); },
          read: async (...args) => {
            if (!changed) {
              changed = true;
              if (mutation === 'replace-during-read') { await rename(file, join(directory, 'previous')); await writeFile(file, 'original input'); }
              if (mutation === 'grow') await writeFile(file, 'original input plus');
              if (mutation === 'shrink') await writeFile(file, 'small');
              if (mutation === 'same-size') await writeFile(file, 'modified input');
            }
            return handle.read(...args);
          } };
      } };
      await assert.rejects(readLocalTemplateArchive(file, operations), /archive_changed|ELOOP/);
      if (mutation !== 'symlink-before-open') assert.equal(closed, true, mutation);
    }
  } finally { await rm(directory, { recursive: true, force: true }); }
});
