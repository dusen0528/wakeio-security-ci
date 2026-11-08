# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Run: pinned Python3.12 -I -B this file. Synthetic inspection DATA, never a fake daemon or owner."""
from __future__ import annotations

import copy
import json
import sys
import unittest
from pathlib import Path
from typing import Final, TypedDict

ROOT: Final = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "workers/runtime-build"), str(ROOT / "workers/runtime-controller")]
from backend_process import BackendError
from input_resources import Json
from preparation_material_data import MaterialFrame, MaterialKind
from preparation_material_inspect import ImageObservation, carrier_observation, image_observation, volume_observation

RUN: Final = "ab" * 16
ID: Final = "cd" * 32
IMAGE: Final = "docker.io/library/maven@sha256:65cedfb84cfbb1dc9974c14662d6bf9b20aa6aea274c877fe08952bdfae7992f"
CONFIG: Final = "sha256:fe1f0cef06dadb4b4e7b613be22c806414f48f3357c9728e659f7bc0baab7326"
FRAME: Final = MaterialFrame(RUN, 7, "carrier-inspect", ID)
IMAGE_DATA: Final = ImageObservation(IMAGE, CONFIG, ("mvn",), ("PATH=/bin",))


class Carrier(TypedDict):
    Id: str
    Image: str
    Config: dict[str, Json]
    HostConfig: dict[str, Json]
    State: dict[str, Json]
    Mounts: list[Json]
    RestartCount: int


def labels(role: str) -> dict[str, Json]:
    return {"wakeio.owner": "t6-build", "wakeio.run": RUN, "wakeio.generation": "7",
            "wakeio.scope": "build", "wakeio.role": "prepare-" + role}


def carrier() -> Carrier:
    mounts: list[Json] = []
    declarations: list[Json] = []
    for kind in ("work", "cache", "output"):
        name = f"wk-{RUN}-b7-prepare-{kind}"
        mounts.append({"Type": "volume", "Name": name, "Driver": "local", "Destination": "/" + kind,
                       "Source": "/home/wakeio-m1/.local/share/docker/volumes/" + name + "/_data",
                       "RW": True, "Propagation": ""})
        declarations.append({"Type": "volume", "Source": name, "Target": "/" + kind,
                             "ReadOnly": False, "VolumeOptions": {"NoCopy": True}})
    return {
        "Id": ID, "Image": CONFIG, "RestartCount": 0, "Mounts": mounts,
        "Config": {"Image": IMAGE, "Labels": labels("transfer"), "Entrypoint": ["/bin/false"],
                   "User": "65532:65532", "Cmd": ["mvn"], "Env": ["PATH=/bin"], "Healthcheck": None,
                   "Volumes": {"/work": {}}, "Tty": False, "OpenStdin": False, "StdinOnce": False,
                   "AttachStdin": False},
        "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                       "CapDrop": ["ALL"], "SecurityOpt": ["no-new-privileges"], "Runtime": "runc",
                       "PidMode": "", "IpcMode": "private", "CgroupParent": "", "UsernsMode": "",
                       "NanoCpus": 2000000000, "Memory": 2147483648, "MemorySwap": 2147483648,
                       "PidsLimit": 256, "RestartPolicy": {"Name": "no", "MaximumRetryCount": 0},
                       "AutoRemove": False, "Mounts": declarations},
        "State": {"Status": "created", "Running": False, "Paused": False, "Restarting": False,
                  "Dead": False, "OOMKilled": False, "Pid": 0, "ExitCode": 0, "Error": "",
                  "StartedAt": "0001-01-01T00:00:00Z", "FinishedAt": "0001-01-01T00:00:00Z"},
    }


class MaterialInspectionTests(unittest.TestCase):
    def test_pinned_image_data_accepts_only_declared_image_allocation_shape(self) -> None:
        base: dict[str, Json] = {"Id": CONFIG, "Os": "linux", "Architecture": "arm64", "RepoDigests": [IMAGE],
                                "Config": {"Cmd": ["mvn"], "Env": ["PATH=/bin"]}}
        self.assertEqual(image_observation(json.dumps([base]).encode()), IMAGE_DATA)
        for change in ({"Id": "sha256:" + ID}, {"Os": "windows"}, {"Architecture": "amd64"},
                       {"RepoDigests": []}, {"Config": {"Volumes": {"/extra": {}}}},
                       {"Config": {"Healthcheck": {"Test": ["CMD", "true"]}}},
                       {"Config": {"Cmd": [False]}}, {"Config": {"Env": ["x" * 4097]}}):
            with self.subTest(change=change), self.assertRaises(BackendError):
                image_observation(json.dumps([{**base, **change}]).encode())

    def test_volume_observations_bind_exact_names_labels_created_and_mountpoint(self) -> None:
        kinds: tuple[MaterialKind, ...] = ("work", "cache", "output")
        for kind in kinds:
            name = f"wk-{RUN}-b7-prepare-{kind}"
            frame = MaterialFrame(RUN, 7, "carrier-create", None)
            raw_frame = frame.data()
            raw_frame["operation"] = "volume-inspect-" + kind
            from preparation_material_data import parse_frame
            selected = parse_frame(raw_frame)
            mount = "/home/wakeio-m1/.local/share/docker/volumes/" + name + "/_data"
            row: dict[str, Json] = {"Name": name, "Driver": "local", "Scope": "local", "Options": None,
                                    "Labels": labels(kind), "Mountpoint": mount, "CreatedAt": "2026-11-08T00:00:00Z"}
            observed = volume_observation(selected, json.dumps([row]).encode())
            self.assertEqual((observed.kind, observed.name, observed.mountpoint, observed.created),
                             (kind, name, mount, "2026-11-08T00:00:00Z"))
            for change in ({"Name": name + "-other"}, {"Driver": "remote"}, {"Scope": "global"},
                           {"Options": {"device": "/tmp"}}, {"Labels": labels("foreign")},
                           {"Mountpoint": mount + "/../elsewhere"}, {"CreatedAt": ""},
                           {"CreatedAt": True}, {"CreatedAt": "x" * 129}, {"CreatedAt": "now\n"}):
                with self.subTest(kind=kind, change=change), self.assertRaises(BackendError):
                    volume_observation(selected, json.dumps([{**row, **change}]).encode())

    def test_created_carrier_accepts_mount_order_without_claiming_history(self) -> None:
        value = carrier()
        carrier_observation(FRAME, IMAGE_DATA, json.dumps([value]).encode())
        value["Mounts"].reverse()
        declarations = value["HostConfig"]["Mounts"]
        assert isinstance(declarations, list)
        declarations.reverse()
        self.assertIsNone(carrier_observation(FRAME, IMAGE_DATA, json.dumps([value]).encode()))

    def test_carrier_refuses_changed_security_types_limits_or_execution_history(self) -> None:
        sections: tuple[tuple[str, tuple[tuple[str, Json], ...]], ...] = (
            ("Config", (("Image", "foreign"), ("Labels", labels("work")), ("Entrypoint", ["/bin/sh"]),
                        ("User", "0"), ("Cmd", ["other"]), ("Env", ["SECRET=yes"]), ("Tty", True),
                        ("OpenStdin", 0), ("Healthcheck", {}), ("Volumes", {"/extra": {}}))),
            ("HostConfig", (("NetworkMode", "host"), ("ReadonlyRootfs", 1), ("Privileged", True),
                            ("CapDrop", []), ("CapAdd", ["SYS_ADMIN"]), ("SecurityOpt", []), ("Runtime", "other"),
                            ("PidMode", "host"), ("IpcMode", "host"), ("CgroupParent", "other.slice"),
                            ("UsernsMode", "host"), ("NanoCpus", 1), ("Memory", 2147483648.0),
                            ("MemorySwap", -1), ("PidsLimit", True), ("Binds", ["/tmp:/work"]),
                            ("Devices", [{}]), ("DeviceRequests", [{}]), ("ExtraHosts", ["a:b"]),
                            ("Dns", ["1.1.1.1"]), ("DnsSearch", ["local"]), ("PortBindings", {"80/tcp": []}),
                            ("Tmpfs", {"/tmp": "rw"}), ("AutoRemove", True),
                            ("RestartPolicy", {"Name": "no", "MaximumRetryCount": False}))),
            ("State", (("Status", "exited"), ("Running", True), ("Paused", True), ("Restarting", True),
                       ("Dead", True), ("OOMKilled", True), ("Pid", False), ("ExitCode", False),
                       ("Error", "error"), ("StartedAt", "2026-11-08T00:00:00Z"))),
        )
        for section, changes in sections:
            for key, changed in changes:
                value = carrier()
                fields = value["Config"] if section == "Config" else (
                    value["HostConfig"] if section == "HostConfig" else value["State"])
                fields[key] = changed
                with self.subTest(section=section, key=key), self.assertRaises(BackendError):
                    carrier_observation(FRAME, IMAGE_DATA, json.dumps([value]).encode())
        for field in ("Id", "Image", "RestartCount"):
            raw = json.loads(json.dumps(carrier()))
            raw[field] = "foreign"
            with self.subTest(field=field), self.assertRaises(BackendError):
                carrier_observation(FRAME, IMAGE_DATA, json.dumps([raw]).encode())

    def test_mount_data_refuses_extra_duplicate_wrong_source_flags_and_nocopy_loss(self) -> None:
        value = carrier()
        original = value["Mounts"]
        mutations = ([], original[:2], [*original, original[0]], [original[0], original[0], original[2]])
        for mounts in mutations:
            value = carrier()
            value["Mounts"] = mounts
            with self.subTest(mounts=mounts), self.assertRaises(BackendError):
                carrier_observation(FRAME, IMAGE_DATA, json.dumps([value]).encode())
        for declared in (False, True):
            changes = (("Source", "/foreign"), ("Type", "bind"), ("ReadOnly", 0),
                       ("VolumeOptions", {"NoCopy": 1})) if declared else (
                           ("Destination", []), ("Source", "/foreign"), ("RW", 1), ("Propagation", "rshared"))
            for key, changed in changes:
                raw = copy.deepcopy(carrier())
                mounts = raw["HostConfig"]["Mounts"] if declared else raw["Mounts"]
                assert isinstance(mounts, list) and isinstance(mounts[0], dict)
                mounts[0][key] = changed
                with self.subTest(declared=declared, key=key), self.assertRaises(BackendError):
                    carrier_observation(FRAME, IMAGE_DATA, json.dumps([raw]).encode())


if __name__ == "__main__":
    unittest.main(verbosity=2)
