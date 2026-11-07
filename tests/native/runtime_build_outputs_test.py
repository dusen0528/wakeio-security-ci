# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Inert file/JAR comparison controls; no Maven, Java, Docker or original build is exercised."""
import errno
import hashlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
import zipfile
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, replace
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "workers/runtime-build"))
from input import profile
from output_files import Binding, DIRECTORY_FLAGS, OutputError
from outputs import CacheFile, ClosureData, inspect_cache, inspect_output

APP = "BOOT-INF/classes/"
LIB = "BOOT-INF/lib/dep-1.jar"
LAUNCHER = "org/springframework/boot/loader/launch/JarLauncher.class"
SERVICE = "META-INF/services/io.example.Service"
MANIFEST = "META-INF/MANIFEST.MF"
CLASSPATH = "BOOT-INF/classpath.idx"
LAYERS = "BOOT-INF/layers.idx"


def binding(path: str, body: bytes) -> Binding:
    return Binding(path, len(body), hashlib.sha256(body).hexdigest())


def archive(bodies: dict[str, bytes], compressed_runtime: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as writer:
        for path, body in bodies.items():
            entry = zipfile.ZipInfo(path)
            entry.external_attr = (stat.S_IFREG | 0o644) << 16
            entry.compress_type = zipfile.ZIP_STORED if path == LIB and not compressed_runtime else zipfile.ZIP_DEFLATED
            writer.writestr(entry, body)
    return buffer.getvalue()


@dataclass(frozen=True, slots=True)
class Fixture:
    """Each test owns the mutable candidate bodies and real files, not the production policy."""
    identifier: str
    root: Path
    cache_root: Path
    output_fd: int
    cache_fd: int
    closure: ClosureData
    bodies: dict[str, bytes]
    class_path: str
    maven: str
    jar_name: str

    def write(self, compressed_runtime: bool = False) -> bytes:
        raw = archive(self.bodies, compressed_runtime)
        (self.root / self.jar_name).write_bytes(raw)
        return raw


@contextmanager
def fixture(identifier: str = "f01") -> Iterator[Fixture]:
    selected = profile(identifier)
    artifact = "primary-sqli" if identifier in ("f01", "f02") else "jdbc-sqli"
    java = selected.files[3].path.removeprefix("src/main/java/").removesuffix(".java")
    class_path = java + ".class"
    maven = "META-INF/maven/io.wakeio.fixtures/" + artifact + "/"
    manifest = ("Manifest-Version: 1.0\nMain-Class: org.springframework.boot.loader.launch.JarLauncher\n"
                "Start-Class: " + java.replace("/", ".") + "\nSpring-Boot-Version: 4.1.2\n"
                "Spring-Boot-Classes: BOOT-INF/classes/\nSpring-Boot-Lib: BOOT-INF/lib/\n"
                "Spring-Boot-Classpath-Index: BOOT-INF/classpath.idx\n"
                "Spring-Boot-Layers-Index: BOOT-INF/layers.idx\n\n")
    loader = {LAUNCHER: b"inert independent launcher bytes", SERVICE: b"inert.Service\n"}
    classes = {class_path: b"inert independent application bytes", "application.properties": b"fixture=true\n"}
    dependency = archive({"inert/record": b"independent dependency record"})
    bodies = {MANIFEST: manifest.encode(), CLASSPATH: ('- "' + LIB + '"\n').encode(),
              LAYERS: ('- "dependencies":\n  - "BOOT-INF/lib/"\n- "spring-boot-loader":\n  - "org/"\n'
                       '- "snapshot-dependencies":\n- "application":\n  - "BOOT-INF/classes/"\n'
                       '  - "BOOT-INF/classpath.idx"\n  - "BOOT-INF/layers.idx"\n  - "META-INF/"\n').encode(),
              maven + "pom.xml": (ROOT / selected.root / "pom.xml").read_bytes(),
              maven + "pom.properties": ("# independent metadata\nversion=1.0.0\n"
                                         "groupId=io.wakeio.fixtures\nartifactId=" + artifact + "\n").encode(),
              LIB: dependency, **loader, **{APP + path: body for path, body in classes.items()}}
    cache_bodies = {"repo/dep/1/dep-1.jar": dependency, "repo/_remote.repositories": b"independent bookkeeping\n"}
    closure = ClosureData(tuple(CacheFile(binding(path, body), "io.example:dep:1" if path.endswith(".jar") else None)
                                for path, body in cache_bodies.items()), ("repo/dep/1/dep-1.jar",),
                          tuple(binding(path, body) for path, body in loader.items()))
    with tempfile.TemporaryDirectory(prefix="output-jar-") as temporary, ExitStack() as stack:
        root, cache_root = Path(temporary) / "output", Path(temporary) / "cache"
        root.mkdir(mode=0o700)
        cache_root.mkdir(mode=0o700)
        for path, body in classes.items():
            target = root / "classes" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        for path, body in cache_bodies.items():
            target = cache_root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(body)
        output_fd = os.open(root, DIRECTORY_FLAGS)
        stack.callback(os.close, output_fd)
        cache_fd = os.open(cache_root, DIRECTORY_FLAGS)
        stack.callback(os.close, cache_fd)
        value = Fixture(identifier, root, cache_root, output_fd, cache_fd, closure, bodies, class_path,
                        maven, artifact + "-1.0.0.jar")
        value.write()
        yield value


class OutputTests(unittest.TestCase):
    def test_each_fixed_profile_retains_its_read_only_jar_and_exact_independent_class_digest(self) -> None:
        for identifier, ending in (("f01", b"\n"), ("f02", b"\r\n"), ("f03", b"\r"), ("f04", b"\n")):
            with self.subTest(profile=identifier), fixture(identifier) as value:
                for path in (value.maven + "pom.properties", LAYERS):
                    value.bodies[path] = value.bodies[path].replace(b"\n", ending)
                value.write()
                cache = inspect_cache(value.cache_fd, value.closure)
                raw = (value.root / value.jar_name).read_bytes()
                expected = [{"path": path[len(APP):], "bytes": len(body), "sha256": hashlib.sha256(body).hexdigest()}
                            for path, body in sorted(value.bodies.items()) if path.startswith(APP)]
                digest = hashlib.sha256(json.dumps(expected, separators=(",", ":")).encode()).hexdigest()
                with inspect_output(value.output_fd, identifier, cache) as result:
                    owned = result.stream.fileno()
                    self.assertFalse(result.stream.writable())
                    self.assertEqual(result.stream.read(), raw)
                    self.assertEqual(result.jar, binding(value.jar_name, raw))
                    self.assertEqual(result.classes_sha256, digest)
                    self.assertEqual([row.path for row in result.classes], [row["path"] for row in expected])
                self.assertTrue(result.stream.closed)
                with self.assertRaises(OSError) as closed:
                    os.fstat(owned)
                self.assertEqual(closed.exception.errno, errno.EBADF)
                self.assertTrue(os.fstat(value.output_fd).st_ino and os.fstat(value.cache_fd).st_ino)

    def test_cache_requires_exact_independent_bytes_and_membership(self) -> None:
        for path, body in (("repo/dep/1/dep-1.jar", b"different dependency"), ("extra", b"unaccounted")):
            with self.subTest(path=path), fixture() as value:
                (value.cache_root / path).write_bytes(body)
                with self.assertRaisesRegex(OutputError, "^cache_files$"):
                    inspect_cache(value.cache_fd, value.closure)

    def test_missing_runtime_or_launcher_inventory_never_becomes_an_accepted_closure(self) -> None:
        with fixture() as value:
            with self.assertRaisesRegex(OutputError, "^cache_runtime$"):
                replace(value.closure, runtime=())
            with self.assertRaisesRegex(OutputError, "^cache_loader_launcher$"):
                replace(value.closure, loader=(binding(SERVICE, b"inert.Service\n"),))
            row = value.closure.files[0]
            with self.assertRaisesRegex(OutputError, "^cache_runtime$"):
                replace(value.closure, files=(replace(row, coordinate=None), *value.closure.files[1:]))

    def test_jar_selection_refuses_a_second_executable_or_an_unexpected_name(self) -> None:
        for name in ("second.jar", "renamed.jar"):
            with self.subTest(name=name), fixture() as value:
                raw = (value.root / value.jar_name).read_bytes()
                if name == "renamed.jar":
                    (value.root / value.jar_name).unlink()
                (value.root / name).write_bytes(raw)
                with self.assertRaisesRegex(OutputError, "^output_jar_selection$"):
                    with inspect_output(value.output_fd, "f01", inspect_cache(value.cache_fd, value.closure)):
                        self.fail("Unexpected executable selection")

    def test_manifest_refuses_unaccounted_execution_attributes_duplicates_and_sections(self) -> None:
        additions = (b"Class-Path: other.jar\n", b"main-class: other.Launcher\n", b"Name: named/section\n")
        for addition in additions:
            with self.subTest(addition=addition), fixture() as value:
                value.bodies[MANIFEST] = value.bodies[MANIFEST][:-1] + addition + b"\n"
                value.write()
                with self.assertRaises(OutputError):
                    with inspect_output(value.output_fd, "f01", inspect_cache(value.cache_fd, value.closure)):
                        self.fail("Unexpected manifest acceptance")

    def test_application_bytes_are_compared_with_the_separately_opened_classes_file(self) -> None:
        with fixture() as value:
            path = APP + value.class_path
            value.bodies[path] = b"X" + value.bodies[path][1:]
            value.write()
            with self.assertRaisesRegex(OutputError, "^jar_class_bytes$"):
                with inspect_output(value.output_fd, "f01", inspect_cache(value.cache_fd, value.closure)):
                    self.fail("Different application bytes were accepted")

    def test_member_binding_and_index_controls_refuse_at_their_own_boundary(self) -> None:
        controls = ((LIB, "jar_binding_digest"), (LAUNCHER, "jar_binding_digest"),
                    ("extra.class", "jar_members"), (CLASSPATH, "jar_classpath"),
                    (LAYERS, "jar_layer_overlap"), ("pom.xml", "jar_binding_digest"),
                    ("pom.properties", "jar_properties"), ("properties-comment-vt", "jar_properties"),
                    ("layers-vt", "jar_layers"))
        for key, reason in controls:
            with self.subTest(key=key), fixture() as value:
                path = value.maven + key if key.startswith("pom.") else key
                if key == "properties-comment-vt":
                    path = value.maven + "pom.properties"
                    body = b"# ignored\vgroupId=io.wakeio.fixtures\vartifactId=primary-sqli\vversion=1.0.0\n"
                elif key == "layers-vt":
                    path = LAYERS
                    body = value.bodies[path].replace(b"\n", b"\v")
                elif key == CLASSPATH:
                    body = value.bodies[key] * 2
                elif key == LAYERS:
                    body = value.bodies[key] + b'  - "BOOT-INF/lib/"\n'
                elif key == "extra.class":
                    body = b"unaccounted inert entry"
                elif key == "pom.properties":
                    body = value.bodies[path].replace(b"1.0.0", b"9.0.0")
                else:
                    body = b"X" + value.bodies[path][1:]
                value.bodies[path] = body
                value.write()
                with self.assertRaisesRegex(OutputError, "^" + reason + "$"):
                    with inspect_output(value.output_fd, "f01", inspect_cache(value.cache_fd, value.closure)):
                        self.fail("A malformed candidate was accepted")

    def test_runtime_jars_must_be_stored_even_when_their_actual_bytes_match(self) -> None:
        with fixture() as value:
            value.write(compressed_runtime=True)
            with self.assertRaisesRegex(OutputError, "^jar_runtime_compression$"):
                with inspect_output(value.output_fd, "f01", inspect_cache(value.cache_fd, value.closure)):
                    self.fail("A compressed runtime JAR was accepted")

    def test_consumer_name_replacement_invalidates_the_context_without_closing_the_borrowed_root(self) -> None:
        with fixture() as value:
            with self.assertRaisesRegex(OutputError, "^output_tree_changed$"):
                with inspect_output(value.output_fd, "f01", inspect_cache(value.cache_fd, value.closure)) as result:
                    replacement = value.root / "replacement"
                    replacement.write_bytes(b"X" * result.jar.bytes)
                    os.replace(replacement, value.root / value.jar_name)
            self.assertTrue(result.stream.closed)
            self.assertTrue(os.fstat(value.output_fd).st_ino)


if __name__ == "__main__":
    unittest.main(verbosity=2)
