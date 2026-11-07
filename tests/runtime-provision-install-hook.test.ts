import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { resolve } from 'node:path';
import test from 'node:test';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const execute = promisify(execFile);
const python = process.env['T6P_TEST_PYTHON'];
if (!python) throw new Error('T6P_TEST_PYTHON must name an installed Python 3.11+ interpreter');
const interpreter = python;
const fixture = `
import sys, hashlib
sys.path.insert(0, ${JSON.stringify(resolve('workers/runtime-controller'))})
from install_config import options
from install_prepare import Prepared
from install_process import Deadline
from seal_files import Files
from seal_hook import validate_install_hook
from seal_operation import Operation
from seal_types import BASE, HOOK, Package, Version, InstallError
import install_supervisor
plan = tuple(Package("fixture-" + str(n), Version("-", "-", "none"), Version("1", "arm64", "none"),
                     "<", "fixture-" + str(n) + "_1_arm64.deb", 10, "a" * 64, "ubuntu")
             for n in range(4))
config = options(9)
wire_config = list(config.items()) + [("APT::Get::Download", "false"), ("DPkg::Pre-Install-Pkgs::", HOOK)]
headers = ["VERSION 3"] + [k + "=" + v for k, v in wire_config if v] + [""]
rows = []
for package in plan:
    prefix = package.name + " - - none < 1 arm64 none "
    rows.extend([prefix + BASE + "/archives/" + package.file, prefix + "**CONFIGURE**"])
payload = ("\\n".join(headers + rows) + "\\n").encode("ascii")
def denied(body, code):
    try:
        validate_install_hook(body, plan, config)
    except InstallError as error:
        assert error.code == code, (error.code, code)
    else:
        raise AssertionError("invalid transaction accepted")
`;

async function exercise(script: string): Promise<void> {
  const root = await mkdtemp(join(tmpdir(), 'install-python-'));
  try {
    const result = await execute(interpreter, ['-I', '-B', '-c', fixture + script], {
      timeout: 10000, maxBuffer: 16384, env: { RUN_TMP: root, TMPDIR: root,
        NODE_COMPILE_CACHE: join(root, 'node'), BUN_RUNTIME_TRANSPILER_CACHE_PATH: join(root, 'bun'),
        PYTHONDONTWRITEBYTECODE: '1' },
    });
    assert.equal(result.stdout, 'verified\n');
    assert.equal(result.stderr, '');
  } finally { await rm(root, { recursive: true, force: true }); }
}

test('InfoFD v3 data validation covers every unpack and configure without claiming an APT run', async () => {
  await exercise(`
assert validate_install_hook(payload, plan, config) == hashlib.sha256(payload).hexdigest()
with Files() as files:
    owner = Operation(files, Deadline(30))
    owner.prepared(Prepared(plan, {}, config, "a" * 64))
    owner.consume()
    assert owner.hook(payload) == hashlib.sha256(payload).hexdigest()
    owner.complete()
    try:
        owner.hook(payload)
    except InstallError as error:
        assert error.code == "operation_phase"
    else:
        raise AssertionError("hook replay accepted")
print("verified")
`);
});

test('actual transaction parser refuses missing duplicate extra removal and substituted deb records', async () => {
  await exercise(`
cases = [
    (("\\n".join(headers + rows[:-1]) + "\\n").encode(), "hook_missing"),
    (payload + (rows[0] + "\\n").encode(), "hook_duplicate"),
    (payload.replace(b"fixture-0 -", b"foreign -"), "hook_extra_package"),
    (payload.replace(b"**CONFIGURE**", b"**REMOVE**", 1), "hook_deb"),
    (payload.replace(b"fixture-0_1_arm64.deb", b"replacement.deb"), "hook_deb"),
    (payload.replace(b"< 1 arm64 none", b"> 1 arm64 none", 1), "hook_direction"),
    (payload.replace(b"< 1 arm64 none", b"< 2 arm64 none", 1), "hook_new"),
]
for body, code in cases:
    denied(body, code)
print("verified")
`);
});

test('InfoFD config rejects changed missing duplicate security options and unapproved execution hooks', async () => {
  await exercise(`
denied(payload.replace(b"APT::Get::Download=false", b"APT::Get::Download=true"),
       "hook_option:apt::get::download")
denied(payload.replace(b"APT::Get::Download=false\\n", b""), "hook_option:apt::get::download")
denied(payload.replace(b"APT::Get::Download=false\\n",
                       b"APT::Get::Download=false\\nAPT::Get::Download=false\\n"),
       "hook_option:apt::get::download")
denied(payload.replace(b"VERSION 3\\n", b"VERSION 3\\nDPkg::Pre-Invoke::=/bin/true\\n"),
       "hook_extra_execution_option")
denied(payload.replace(b"VERSION 3", b"VERSION 2"), "hook_version")
denied(payload.replace(b"VERSION 3\\n", b"VERSION 3\\nbad=%FF\\n"), "hook_escape")
print("verified")
`);
});

test('signed-record URI parser rejects alternate authorities and encoded path escapes', async () => {
  await exercise(`
from install_records import package_uri, installed
assert package_uri("https://ports.ubuntu.com/ubuntu-ports/pool/main/f/foo/foo_1_arm64.deb") == "ubuntu"
for uri in (
    "http://ports.ubuntu.com/ubuntu-ports/pool/main/f/foo/foo_1_arm64.deb",
    "https://ports.ubuntu.com.evil/ubuntu-ports/pool/main/f/foo/foo_1_arm64.deb",
    "https://ports.ubuntu.com/ubuntu-ports/pool/main/f/foo/%2e%2e/foo_1_arm64.deb",
    "https://ports.ubuntu.com/ubuntu-ports/pool/main/f/foo/foo_1_arm64.deb?redirect=x",
):
    try:
        package_uri(uri)
    except InstallError:
        pass
    else:
        raise AssertionError(uri)
status = b"Package: foo\\nStatus: install ok installed\\nVersion: 1\\nArchitecture: arm64\\n"
assert installed(status)["foo"] == Version("1", "arm64", "none")
for state in (b"unpacked", b"half-configured", b"triggers-pending"):
    try:
        installed(status.replace(b"ok installed", b"ok " + state))
    except InstallError as error:
        assert error.code == "unclean_dpkg_state"
    else:
        raise AssertionError(state)
print("verified")
`);
});
