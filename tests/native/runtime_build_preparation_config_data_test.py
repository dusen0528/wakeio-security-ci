# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B this file; no commands encoded here are executed.
"""C3 machine schema, XML policy and command boundary regressions."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
import xml.etree.ElementTree as ET
from dataclasses import FrozenInstanceError
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from preparation_config_data import (
    GLOBAL_SETTINGS, USER_SETTINGS, ConfigError, ConfigFrame, Json, Operation, ToolRole,
    command, parse_frame, unit_bytes,
)

RUN: Final = "ab" * 16
ID: Final = "cd" * 32
PREFIX: Final = ("/usr/bin/docker", "--host=unix:///run/user/10001/docker.sock")
IMAGE: Final = "docker.io/library/maven@sha256:65cedfb84cfbb1dc9974c14662d6bf9b20aa6aea274c877fe08952bdfae7992f"
ROLES: Final[tuple[ToolRole, ...]] = ("seed", "input-seed", "producer", "verifier")


class ConfigDataTests(unittest.TestCase):
    def test_boundary_exception_supports_standard_traceback_assignment(self) -> None:
        error = ConfigError("boundary_failure")
        try:
            raise error
        except ConfigError as caught:
            caught.__traceback__ = caught.__traceback__
            self.assertEqual((caught.reason, str(caught)), ("boundary_failure", "boundary_failure"))
            self.assertIsNotNone(caught.__traceback__)

    def test_exact_xml_bytes_select_only_fixed_mirror_and_local_repository(self) -> None:
        cases = ((USER_SETTINGS, 371, "b176f5c0ff795e6a26242f4e06b216468e3d941cebcba9f703fe9149f5d6c5bd"),
                 (GLOBAL_SETTINGS, 98, "bc42fef25e3648c6f2c7175567ab79758d878faa347b6972b4170324878aab8e"))
        for raw, size, digest in cases:
            with self.subTest(size=size):
                self.assertEqual((len(raw), hashlib.sha256(raw).hexdigest()), (size, digest))
        ns = "{http://maven.apache.org/SETTINGS/1.2.0}"
        settings = ET.fromstring(USER_SETTINGS)
        self.assertEqual([child.tag for child in settings],
                         [ns + "localRepository", ns + "interactiveMode", ns + "mirrors"])
        self.assertEqual(settings.findtext(ns + "localRepository"), "/tmp/wakeio-m2")
        mirror = settings.find(ns + "mirrors/" + ns + "mirror")
        assert mirror is not None
        self.assertEqual([(child.tag.removeprefix(ns), child.text) for child in mirror],
                         [("id", "wakeio-build-mirror"), ("mirrorOf", "*"),
                          ("url", "https://wakeio-maven:8443/maven2/")])
        self.assertEqual(list(ET.fromstring(GLOBAL_SETTINGS)), [])

    def test_closed_operation_role_container_and_effect_table(self) -> None:
        rows = (
            ("volume-inspect", (None,), False, True, False),
            ("volume-create", (None,), False, False, True),
            ("volume-remove", (None,), False, True, True),
            ("input-volume-inspect", (None,), False, True, False),
            ("input-volume-create", (None,), False, False, True),
            ("input-volume-remove", (None,), False, True, True),
            ("container-create", ROLES, False, False, True),
            ("container-inspect", ROLES, True, True, False),
            ("container-remove", ROLES, True, True, True),
            ("seed-volume", ("seed",), True, False, True),
            ("seed-inputs", ("input-seed",), True, False, True),
            ("read-inputs", ("input-seed",), True, False, False),
            ("read-config", ("seed", "verifier"), True, False, False),
            ("read-helper", ("producer", "verifier"), True, False, False),
            ("read-certificate", ("producer", "verifier"), True, False, False),
            ("attach-start", ("producer", "verifier"), True, False, True),
            ("container-kill", ("producer", "verifier"), True, True, True),
            ("envelope-present", ("producer", "verifier"), False, True, False),
            ("envelope-files", ("producer", "verifier"), False, True, False),
            ("envelope-inspect", ("producer", "verifier"), False, True, False),
            ("envelope-reload", ("producer", "verifier"), False, True, True),
            ("envelope-start", ("producer", "verifier"), False, False, True),
            ("envelope-stop", ("producer", "verifier"), False, True, True),
        )
        for op, allowed, needs_id, cleanup, mutation in rows:
            for role in (None, *ROLES):
                for identifier in (None, ID):
                    raw: dict[str, Json] = {"run": RUN, "generation": 7, "operation": op,
                                            "tool": role, "container": identifier}
                    with self.subTest(op=op, role=role, identifier=identifier):
                        if role in allowed and (identifier is not None) == needs_id:
                            frame = parse_frame(raw)
                            self.assertEqual((frame.cleanup, frame.mutation), (cleanup, mutation))
                            self.assertEqual(frame.data(), raw)
                        else:
                            with self.assertRaises(ConfigError):
                                parse_frame(raw)

    def test_mapping_and_constructor_refuse_types_bounds_and_authority_fields(self) -> None:
        base: dict[str, Json] = {"run": RUN, "generation": 7, "operation": "read-config",
                                "tool": "verifier", "container": ID}
        for change in (
            {"run": RUN.upper()}, {"run": RUN + "0"}, {"run": None}, {"generation": True},
            {"generation": 1.0}, {"generation": 0}, {"generation": 10**16}, {"operation": "release"},
            {"operation": "terminal-read"}, {"operation": None}, {"tool": "offline"}, {"tool": True},
            {"container": ID.upper()}, {"container": ID[:-1]}, {"container": False}, {"mode": "terminal"},
            {"deadline": 1}, {"argv": []}, {"owner": {}},
        ):
            with self.subTest(change=change), self.assertRaises(ConfigError):
                parse_frame({**base, **change})
        with self.assertRaises(ConfigError):
            parse_frame(dict(reversed(tuple(base.items()))))
        with self.assertRaises(ConfigError):
            ConfigFrame(RUN, True, Operation.READ_CONFIG, "verifier", ID)
        frame = ConfigFrame(RUN, 9999999999999999, Operation.READ_CONFIG, "verifier", ID)
        with self.assertRaises(FrozenInstanceError):
            setattr(frame, "generation", 2)
        self.assertLessEqual(len(json.dumps({"role": "preparation-config", "operand": frame.data()},
                                           separators=(",", ":")).encode()), 1024)

    def test_fixed_copy_and_control_argv_cannot_encode_exec_or_arbitrary_paths(self) -> None:
        rows: tuple[tuple[Operation, ToolRole, tuple[str, ...]], ...] = (
            (Operation.SEED_VOLUME, "seed", ("cp", "--archive", "-", ID + ":/build-config")),
            (Operation.SEED_INPUTS, "input-seed", ("cp", "--archive", "-", ID + ":/config-input")),
            (Operation.READ_INPUTS, "input-seed", ("cp", "--archive", ID + ":/config-input", "-")),
            (Operation.READ_CONFIG, "verifier", ("cp", "--archive", ID + ":/build-config", "-")),
            (Operation.READ_HELPER, "producer", ("cp", "--archive", ID + ":/config-input/producer", "-")),
            (Operation.READ_CERTIFICATE, "verifier", ("cp", "--archive", ID + ":/config-input/mirror.crt", "-")),
            (Operation.ATTACH_START, "producer", ("start", "--attach", ID)),
            (Operation.CONTAINER_KILL, "verifier", ("container", "kill", ID)),
            (Operation.CONTAINER_REMOVE, "seed", ("container", "rm", ID)),
            (Operation.CONTAINER_INSPECT, "input-seed", ("container", "inspect", ID)),
        )
        for op, role, suffix in rows:
            with self.subTest(op=op):
                self.assertEqual(command(ConfigFrame(RUN, 7, op, role, ID)), (*PREFIX, *suffix))
        for auxiliary in (False, True):
            op = Operation.INPUT_VOLUME_REMOVE if auxiliary else Operation.VOLUME_REMOVE
            name = f"wk-{RUN}-b7-prepare-config" + ("-input" if auxiliary else "")
            self.assertEqual(command(ConfigFrame(RUN, 7, op, None, None)), (*PREFIX, "volume", "rm", name))

    def test_tool_creation_has_exact_roles_mounts_java_env_and_security(self) -> None:
        common = (*PREFIX, "create", "--network=none", "--read-only", "--cap-drop=ALL",
                  "--security-opt=no-new-privileges", "--user=65532:65532", "--cpus=2",
                  "--memory=2147483648", "--memory-swap=2147483648", "--pids-limit=256",
                  "--runtime=runc", "--ipc=private", "--restart=no", "--workdir=/tmp")
        for role in ROLES:
            frame = ConfigFrame(RUN, 7, Operation.CONTAINER_CREATE, role, None)
            argv = command(frame)
            self.assertEqual(argv[:len(common)], common)
            mounts = tuple(arg for arg in argv if arg.startswith("--mount="))
            config = f"--mount=type=volume,src=wk-{RUN}-b7-prepare-config,dst=/build-config,volume-nocopy"
            inputs = f"--mount=type=volume,src=wk-{RUN}-b7-prepare-config-input,dst=/config-input,volume-nocopy"
            expected = (inputs,) if role == "input-seed" else ((config,) if role == "seed" else (
                config + (",readonly" if role == "verifier" else ""), inputs + ",readonly"))
            with self.subTest(role=role):
                self.assertEqual(mounts, expected)
                index = argv.index(IMAGE)
                self.assertEqual(argv[index - 1], "--entrypoint=" + (
                    "/bin/false" if role in ("seed", "input-seed") else "/opt/java/openjdk/bin/java"))
                if role in ("producer", "verifier"):
                    env = dict(item[6:].split("=", 1) for item in argv if item.startswith("--env="))
                    self.assertEqual(env, {
                        "PATH": "/opt/java/openjdk/bin:/usr/bin:/bin", "JAVA_HOME": "/opt/java/openjdk",
                        "LANG": "C", "LANGUAGE": "C", "LC_ALL": "C", "JAVA_VERSION": "jdk-21.0.12.1+1",
                        "MAVEN_HOME": "/usr/share/maven", "MAVEN_CONFIG": "/tmp/unused-maven-home",
                        "HOME": "/tmp", "TMPDIR": "/tmp", "HOSTNAME": "wakeio-config-" + role,
                    })
                    name = "PrepConfigProduce.java" if role == "producer" else "PrepConfigVerify.java"
                    self.assertEqual(argv[index + 1:], (
                        "-Djava.io.tmpdir=/tmp", "-Duser.home=/tmp", "-Dfile.encoding=UTF-8",
                        "--class-path", "/config-input/" + role, "--source", "21",
                        "/config-input/" + role + "/" + name))
                else:
                    self.assertEqual(argv[index + 1:], ())
                    self.assertEqual([arg for arg in argv if arg.startswith("--env=")], [])

    def test_envelope_units_and_commands_use_fresh_fixed_role_names(self) -> None:
        for role, ending in (("producer", "produce"), ("verifier", "verify")):
            raw: dict[str, Json] = {"run": RUN, "generation": 7, "operation": "envelope-start",
                                    "tool": role, "container": None}
            frame = parse_frame(raw)
            name = f"wk{RUN}b7config{ending}.slice"
            self.assertEqual(command(frame), ("/usr/bin/systemctl", "--user", "start", name))
            self.assertEqual(unit_bytes(frame), (
                f"[Unit]\nDescription=Wakeio configuration {role}\n[Slice]\nCPUQuota=200%\n"
                "MemoryMax=2147483648\nMemorySwapMax=0\nTasksMax=256\n").encode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
