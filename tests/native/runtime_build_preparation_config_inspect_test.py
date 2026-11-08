# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
# Run: pinned Python3.12 -I -B this file. Inspection JSON is inert DATA, never a fake owner.
"""Strict machine observations for C3 volumes, tools and semantic bindings."""
from __future__ import annotations

import hashlib
import json
import sys
import unittest
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from preparation_config_data import ConfigError, ConfigFrame, Json, Operation, ToolRole
from preparation_config_inspect import (
    Verification, container_observation, image_observation, semantic_observation, volume_observation,
)

RUN: Final = "ab" * 16
ID: Final = "cd" * 32
IMAGE: Final = "docker.io/library/maven@sha256:65cedfb84cfbb1dc9974c14662d6bf9b20aa6aea274c877fe08952bdfae7992f"
CONFIG: Final = "sha256:fe1f0cef06dadb4b4e7b613be22c806414f48f3357c9728e659f7bc0baab7326"
VOLUMES: Final = "/home/wakeio-m1/.local/share/docker/volumes/"
ZERO: Final = "0001-01-01T00:00:00Z"
NOW: Final = "2026-11-08T00:00:00Z"
BASE_ENV: Final = ["PATH=/bin", "JAVA_HOME=/opt/java/openjdk", "LANG=C", "LANGUAGE=C", "LC_ALL=C",
                   "JAVA_VERSION=jdk-21.0.12.1+1", "MAVEN_HOME=/usr/share/maven", "MAVEN_CONFIG=/root/.m2"]


def wire(value: Json) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("utf-8")


def image() -> dict[str, Json]:
    return {"Id": CONFIG, "Os": "linux", "Architecture": "arm64", "RepoDigests": [IMAGE],
            "Config": {"Cmd": ["mvn"], "Env": list(BASE_ENV)}}


def labels(role: str) -> dict[str, Json]:
    return {"wakeio.owner": "t6-build", "wakeio.run": RUN, "wakeio.generation": "7",
            "wakeio.scope": "build", "wakeio.role": "prepare-" + role}


def container(role: ToolRole) -> dict[str, Json]:
    started = role in ("producer", "verifier")
    name = f"wk-{RUN}-b7-prepare-config"
    targets = (("/build-config", name, role == "verifier"), ("/config-input", name + "-input", True)) \
        if started else ((("/config-input", name + "-input", False),) if role == "input-seed" else (
            ("/build-config", name, False),))
    env = [*BASE_ENV]
    cmd = ["mvn"]
    host: dict[str, Json] = {
        "NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"],
        "SecurityOpt": ["no-new-privileges"], "Runtime": "runc", "PidMode": "", "IpcMode": "private",
        "CgroupParent": "", "UsernsMode": "", "UTSMode": "", "PublishAllPorts": False,
        "NanoCpus": 2000000000, "Memory": 2147483648, "MemorySwap": 2147483648, "PidsLimit": 256,
        "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0}, "AutoRemove": False,
    }
    if started:
        env = ["PATH=/opt/java/openjdk/bin:/usr/bin:/bin", *BASE_ENV[1:7],
               "MAVEN_CONFIG=/tmp/unused-maven-home", "HOME=/tmp", "TMPDIR=/tmp", "HOSTNAME=wakeio-config-" + role]
        filename = "PrepConfigProduce.java" if role == "producer" else "PrepConfigVerify.java"
        cmd = ["-Djava.io.tmpdir=/tmp", "-Duser.home=/tmp", "-Dfile.encoding=UTF-8", "--class-path",
               "/config-input/" + role, "--source", "21", "/config-input/" + role + "/" + filename]
        ending = "produce" if role == "producer" else "verify"
        host["CgroupParent"] = f"wk{RUN}b7config{ending}.slice"
        host["Tmpfs"] = {"/tmp": "rw,nosuid,nodev,noexec,size=268435456,mode=1777"}
    mounts: list[Json] = [
        {"Type": "volume", "Name": volume, "Source": VOLUMES + volume + "/_data",
         "Destination": target, "Driver": "local", "RW": not readonly, "Propagation": ""}
        for target, volume, readonly in targets]
    host["Mounts"] = [{"Type": "volume", "Source": volume, "Target": target,
                       "ReadOnly": readonly, "VolumeOptions": {"NoCopy": True}}
                      for target, volume, readonly in targets]
    return {
        "Id": ID, "Image": CONFIG, "Created": NOW, "RestartCount": 0, "Mounts": mounts,
        "NetworkSettings": {"Networks": {"none": {}}},
        "Config": {"Image": IMAGE, "Labels": labels("config-" + role), "User": "65532:65532",
                   "WorkingDir": "/tmp", "Cmd": cmd, "Env": env, "Hostname": "wakeio-config-" + role,
                   "Entrypoint": ["/opt/java/openjdk/bin/java" if started else "/bin/false"],
                   "Tty": False, "OpenStdin": False, "StdinOnce": False, "AttachStdin": False},
        "HostConfig": host,
        "State": {"Status": "created", "Running": False, "Paused": False, "Restarting": False,
                  "Dead": False, "OOMKilled": False, "Pid": 0, "ExitCode": 0, "Error": "",
                  "StartedAt": ZERO, "FinishedAt": ZERO},
    }


def semantic() -> dict[str, Json]:
    return {"schema": "wakeio.prep-config.verify/v1", "storeType": "PKCS12", "storeProvider": "SUN",
            "aliases": ["wakeio-build-mirror"], "trustedCertificateEntries": 1, "keyEntries": 0,
            "certificateDerSha256": hashlib.sha256(b"inert DER").hexdigest(),
            "storeSha256": hashlib.sha256(b"inert store").hexdigest(),
            "userSettingsSha256": "b176f5c0ff795e6a26242f4e06b216468e3d941cebcba9f703fe9149f5d6c5bd",
            "globalSettingsSha256": "bc42fef25e3648c6f2c7175567ab79758d878faa347b6972b4170324878aab8e"}


class ConfigInspectionTests(unittest.TestCase):
    def test_image_rejects_wrong_identity_allocations_unknown_and_duplicate_env(self) -> None:
        observed = image_observation(wire([image()]))
        self.assertEqual((observed.reference, observed.config, observed.command), (IMAGE, CONFIG, ("mvn",)))
        for changes in ({"Id": ID}, {"Os": "windows"}, {"Architecture": "amd64"}, {"RepoDigests": []},
                        {"Config": {"Cmd": ["mvn"], "Env": [*BASE_ENV, "JAVA_TOOL_OPTIONS=-agentlib:x"]}},
                        {"Config": {"Cmd": ["mvn"], "Env": [*BASE_ENV, BASE_ENV[0]]}},
                        {"Config": {"Env": BASE_ENV, "Volumes": {"/work": {}}}},
                        {"Config": {"Env": BASE_ENV, "Healthcheck": {"Test": ["CMD", "x"]}}}):
            with self.subTest(changes=changes), self.assertRaises(ConfigError):
                image_observation(wire([{**image(), **changes}]))

    def test_volumes_preserve_four_field_shape_and_exact_binding(self) -> None:
        for auxiliary in (False, True):
            op = Operation.INPUT_VOLUME_INSPECT if auxiliary else Operation.VOLUME_INSPECT
            frame = ConfigFrame(RUN, 7, op, None, None)
            name = f"wk-{RUN}-b7-prepare-config" + ("-input" if auxiliary else "")
            kind = "config-input" if auxiliary else "config"
            row: dict[str, Json] = {"Name": name, "Driver": "local", "Scope": "local",
                                    "Options": None, "Labels": labels(kind),
                                    "Mountpoint": VOLUMES + name + "/_data", "CreatedAt": NOW}
            observed = volume_observation(frame, wire([row]))
            self.assertEqual((observed.kind, observed.name, observed.created, observed.mountpoint),
                             (kind, name, NOW, VOLUMES + name + "/_data"))
            for changes in ({"Name": name + "x"}, {"Driver": "remote"}, {"Options": {"device": "/tmp"}},
                            {"Labels": labels("foreign")}, {"Mountpoint": "/tmp"}, {"CreatedAt": False},
                            {"CreatedAt": ""}, {"CreatedAt": "x" * 129}, {"CreatedAt": "now\n"}):
                with self.subTest(changes=changes), self.assertRaises(ConfigError):
                    volume_observation(frame, wire([{**row, **changes}]))

    def test_created_tools_and_terminal_exit_are_data_not_close_or_owner(self) -> None:
        roles: tuple[ToolRole, ...] = ("seed", "input-seed", "producer", "verifier")
        for role in roles:
            frame = ConfigFrame(RUN, 7, Operation.CONTAINER_INSPECT, role, ID)
            row = container(role)
            observed = container_observation(frame, image_observation(wire([image()])), wire([row]))
            self.assertEqual((observed.identifier, observed.created, observed.status), (ID, NOW, "created"))
            if role in ("producer", "verifier"):
                state = row["State"]
                assert isinstance(state, dict)
                state.update({"Status": "exited", "StartedAt": NOW, "FinishedAt": NOW, "ExitCode": 42})
                result = container_observation(frame, image_observation(wire([image()])), wire([row]))
                self.assertEqual((result.status, result.exit_code), ("exited", 42))

    def test_tool_security_and_history_drift_refuse(self) -> None:
        frame = ConfigFrame(RUN, 7, Operation.CONTAINER_INSPECT, "verifier", ID)
        img = image_observation(wire([image()]))
        changes: tuple[tuple[str, str, Json], ...] = (
            ("Config", "Env", [*BASE_ENV]), ("Config", "Cmd", ["mvn"]),
            ("Config", "Volumes", {"/work": {}}), ("Config", "User", "0"), ("Config", "Tty", 0),
            ("Config", "Hostname", "foreign"), ("Config", "ExposedPorts", {"80/tcp": {}}),
            ("HostConfig", "ReadonlyRootfs", 1), ("HostConfig", "NetworkMode", "host"),
            ("HostConfig", "Memory", 2147483648.0), ("HostConfig", "PidsLimit", True),
            ("HostConfig", "CapAdd", ["SYS_ADMIN"]), ("HostConfig", "SecurityOpt", ["seccomp=unconfined"]),
            ("HostConfig", "CgroupParent", "other.slice"), ("HostConfig", "Tmpfs", {"/tmp": "rw"}),
            ("HostConfig", "RestartPolicy", {"Name": "no", "MaximumRetryCount": False}),
            ("HostConfig", "GroupAdd", ["0"]), ("HostConfig", "DeviceRequests", [{}]),
            ("HostConfig", "Binds", ["/tmp:/work"]), ("HostConfig", "UTSMode", "host"),
            ("State", "Status", "running"), ("State", "Pid", False), ("State", "ExitCode", False),
            ("State", "Running", True), ("State", "Error", "failed"), ("State", "StartedAt", NOW),
        )
        for section, key, value in changes:
            row = container("verifier")
            fields = row[section]
            assert isinstance(fields, dict)
            fields[key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ConfigError):
                container_observation(frame, img, wire([row]))

    def test_mounts_and_inspection_json_cannot_alias_or_hide_fields(self) -> None:
        frame = ConfigFrame(RUN, 7, Operation.CONTAINER_INSPECT, "producer", ID)
        img = image_observation(wire([image()]))
        for field, changed in (("Destination", []), ("Source", "/tmp"), ("RW", 1),
                               ("Propagation", "rshared"), ("Type", "bind")):
            row = container("producer")
            mounts = row["Mounts"]
            assert isinstance(mounts, list) and isinstance(mounts[0], dict)
            mounts[0][field] = changed
            with self.subTest(field=field), self.assertRaises(ConfigError):
                container_observation(frame, img, wire([row]))
        for field, changed in (("ReadOnly", 0), ("VolumeOptions", {"NoCopy": 1}), ("Source", "foreign")):
            row = container("producer")
            host = row["HostConfig"]
            assert isinstance(host, dict)
            declared = host["Mounts"]
            assert isinstance(declared, list) and isinstance(declared[0], dict)
            declared[0][field] = changed
            with self.subTest(declared=field), self.assertRaises(ConfigError):
                container_observation(frame, img, wire([row]))
        valid = wire([container("producer")])
        for raw in (valid[:-1], b"\xef\xbb\xbf" + valid, valid + valid, b"[]",
                    valid.replace(b'"Id":', b'"Id":"other","Id":', 1), b"x" * 131073):
            with self.subTest(raw=raw[:20]), self.assertRaises(ConfigError):
                container_observation(frame, img, raw)

    def test_semantic_output_requires_all_actual_digests_and_entry_semantics(self) -> None:
        expected = Verification(hashlib.sha256(b"inert DER").hexdigest(), hashlib.sha256(b"inert store").hexdigest())
        raw = wire(semantic()) + b"\n"
        self.assertEqual(semantic_observation(raw, expected), expected)
        for changes in ({"storeType": "JKS"}, {"storeProvider": "other"}, {"aliases": ["a", "b"]},
                        {"trustedCertificateEntries": True}, {"keyEntries": False}, {"keyEntries": 1},
                        {"certificateDerSha256": "0" * 64}, {"storeSha256": "A" * 64},
                        {"userSettingsSha256": "0" * 64}, {"globalSettingsSha256": "0" * 64}, {"owner": "yes"}):
            with self.subTest(changes=changes), self.assertRaises(ConfigError):
                semantic_observation(wire({**semantic(), **changes}) + b"\n", expected)
        for malformed in (raw[:-1], raw + raw, b"\xef\xbb\xbf" + raw, raw[:-1] + b" \n",
                          raw.replace(b'"keyEntries":0', b'"keyEntries":0,"keyEntries":0'),
                          raw.replace(b'"keyEntries":0', b'"keyEntries":NaN'), b"x" * 2049):
            with self.subTest(raw=malformed[:20]), self.assertRaises(ConfigError):
                semantic_observation(malformed, expected)


if __name__ == "__main__":
    unittest.main(verbosity=2)
