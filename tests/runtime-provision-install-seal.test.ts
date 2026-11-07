import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import test from 'node:test';
import { resolve } from 'node:path';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const execute = promisify(execFile);
const python = process.env['T6P_TEST_PYTHON'];
if (!python) throw new Error('T6P_TEST_PYTHON must name an installed Python 3.11+ interpreter');
const interpreter = python;
const prelude = `
import os, sys, tempfile, json, socket
sys.path.insert(0, ${JSON.stringify(resolve('workers/runtime-controller'))})
from seal_files import Files, write_new
from seal_types import InstallError
def denied(action, code):
    try:
        action()
    except InstallError as error:
        assert error.code == code, (error.code, code)
    else:
        raise AssertionError("operation accepted")
`;

async function exercise(script: string): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), 'install-python-'));
  try {
    const result = await execute(interpreter, ['-I', '-B', '-c', prelude + script], {
      timeout: 10000, maxBuffer: 16384, env: { RUN_TMP: root, TMPDIR: root,
        NODE_COMPILE_CACHE: join(root, 'node'), BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun'),
        PYTHONDONTWRITEBYTECODE: '1' },
    });
    assert.equal(result.stdout, 'verified\n');
    assert.equal(result.stderr, '');
  } finally { await rm(root, { recursive: true, force: true }); }
}

test('original FD survives a real process boundary while equal-byte pathname replacement is rejected', async () => {
  await exercise(`
with tempfile.TemporaryDirectory(dir=os.path.realpath(os.environ["TMPDIR"])) as root, Files() as files:
    path = root + "/index"
    write_new(path, b"original")
    anchor = files.capture(path, 32)
    left, right = socket.socketpair()
    with left, right:
        pid = os.fork()
        if pid == 0:
            left.close()
            assert right.recv(1) == b"G"
            right.sendall(os.pread(anchor.fd, 8, 0))
            os._exit(0)
        right.close()
        try:
            os.rename(path, root + "/retained")
            write_new(path, b"original")
            left.sendall(b"G")
            assert left.recv(8) == b"original"
            denied(files.check, "name_replaced")
        finally:
            _, status = os.waitpid(pid, 0)
            assert status == 0
print("verified")
`);
});

test('original anchors reject changed config bytes and added empty-directory entries', async () => {
  await exercise(`
with tempfile.TemporaryDirectory(dir=os.path.realpath(os.environ["TMPDIR"])) as root:
    path = root + "/apt.conf"
    write_new(path, b"secure")
    with Files() as files:
        files.capture(path, 32)
        with open(path, "r+b") as stream:
            stream.write(b"unsafe")
        denied(files.check, "name_replaced")
    empty = root + "/empty"
    os.mkdir(empty, 0o700)
    with Files() as files:
        files.directory(empty)
        write_new(empty + "/inherited-hook", b"execute")
        denied(files.check, "directory_replaced")
print("verified")
`);
});

test('file acquisition rejects symlinks, hardlinks and oversized inputs before sealing', async () => {
  await exercise(`
with tempfile.TemporaryDirectory(dir=os.path.realpath(os.environ["TMPDIR"])) as root:
    path = root + "/deb"
    write_new(path, b"1234")
    with Files() as files:
        denied(lambda: files.capture(path, 3), "file_bound")
    os.link(path, root + "/alias")
    with Files() as files:
        denied(lambda: files.capture(path, 4), "file_links_mode")
    os.symlink(path, root + "/link")
    with Files() as files:
        try:
            files.capture(root + "/link", 4)
        except OSError:
            pass
        else:
            raise AssertionError("symlink accepted")
print("verified")
`);
});

test('closed owner releases the actual original descriptor and refuses further checks', async () => {
  await exercise(`
with tempfile.TemporaryDirectory(dir=os.path.realpath(os.environ["TMPDIR"])) as root:
    path = root + "/key"
    write_new(path, b"key")
    with Files() as files:
        anchor = files.capture(path, 3)
        assert anchor.read() == b"key"
    denied(files.check, "closed_files")
    try:
        os.fstat(anchor.fd)
    except OSError as error:
        import errno
        assert error.errno == errno.EBADF
    else:
        raise AssertionError("descriptor leaked")
print("verified")
`);
});

const operation = `
from install_prepare import Prepared
from install_process import Deadline
from seal_operation import Operation
from unittest.mock import patch
prepared = Prepared((), {}, {}, "a" * 64)
`;

test('original process alone consumes once and replay permanently invalidates the owner', async () => {
  await exercise(operation + `
with Files() as files:
    owner = Operation(files, Deadline(30))
    owner.prepared(prepared)
    pid = os.fork()
    if pid == 0:
        denied(owner.consume, "operation_owner")
        os._exit(0)
    assert os.waitpid(pid, 0)[1] == 0
    assert owner.consume() is prepared
    denied(owner.consume, "operation_phase")
    denied(lambda: owner.prepared(prepared), "operation_phase")
print("verified")
`);
});

test('deadline expiration and explicit abort prevent dispatch without timing luck', async () => {
  await exercise(operation + `
with patch("install_process.time.monotonic", return_value=10) as clock, Files() as files:
    owner = Operation(files, Deadline(1))
    owner.prepared(prepared)
    clock.return_value = 11
    denied(owner.consume, "deadline_expired")
    clock.return_value = 10
    denied(owner.consume, "operation_phase")
with Files() as files:
    owner = Operation(files, Deadline(30))
    owner.prepared(prepared)
    owner.close()
    denied(owner.consume, "operation_phase")
print("verified")
`);
});
