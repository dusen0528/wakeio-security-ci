"""Controller-held output observations. Comparison DATA is not provenance, sealing or authority."""
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import BinaryIO, Final

from input import profile
from output_files import Binding, Limits, bindings_digest, require, scan
from output_jar import JarPolicy, inspect
from output_zip import MAX_JAR

CACHE_LIMITS: Final = Limits(1024 * 1024 * 1024, 16384)
OUTPUT_LIMITS: Final = Limits(1024 * 1024 * 1024, 16384)
LAUNCHER_PATH: Final = "org/springframework/boot/loader/launch/JarLauncher.class"


@dataclass(frozen=True, slots=True)
class CacheFile:
    binding: Binding
    coordinate: str | None = None

    def __post_init__(self) -> None:
        require(type(self.binding) is Binding, "cache_binding")
        if self.coordinate is not None:
            require(type(self.coordinate) is str and self.binding.path.endswith(".jar")
                    and re.fullmatch(r"[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+:[A-Za-z0-9_.-]+(?::[A-Za-z0-9_.-]+)?",
                                     self.coordinate) is not None, "cache_coordinate")


@dataclass(frozen=True, slots=True)
class ClosureData:
    """An independently supplied exact inventory; constructibility grants no build eligibility."""
    files: tuple[CacheFile, ...]
    runtime: tuple[str, ...]
    loader: tuple[Binding, ...]

    def __post_init__(self) -> None:
        require(type(self.files) is tuple and 0 < len(self.files) <= CACHE_LIMITS.files
                and all(type(row) is CacheFile for row in self.files), "cache_closure")
        require(sum(row.binding.bytes for row in self.files) <= CACHE_LIMITS.bytes, "cache_closure_bound")
        files = {row.binding.path: row for row in self.files}
        require(len({path.casefold() for path in files}) == len(self.files), "cache_closure_duplicate")
        coordinates = [row.coordinate for row in self.files if row.coordinate is not None]
        require(len(set(coordinates)) == len(coordinates), "cache_coordinate_duplicate")
        require(type(self.runtime) is tuple and 0 < len(self.runtime) <= 4096
                and all(type(path) is str and path in files and files[path].coordinate is not None
                        for path in self.runtime), "cache_runtime")
        names = tuple(PurePosixPath(path).name for path in self.runtime)
        require(len({name.casefold() for name in names}) == len(names), "cache_runtime_duplicate")
        require(sum(files[path].binding.bytes for path in self.runtime) <= MAX_JAR, "cache_runtime_bound")
        require(type(self.loader) is tuple and 0 < len(self.loader) <= 16384
                and all(type(row) is Binding for row in self.loader), "cache_loader")
        require(len({row.path.casefold() for row in self.loader}) == len(self.loader)
                and sum(row.bytes for row in self.loader) <= 16 * 1024 * 1024, "cache_loader_bound")
        for row in self.loader:
            require((row.path.startswith("org/springframework/boot/loader/") and row.path.endswith(".class"))
                    or row.path.startswith("META-INF/services/"), "cache_loader_path")
        require(LAUNCHER_PATH in {row.path for row in self.loader}, "cache_loader_launcher")


@dataclass(frozen=True, slots=True)
class CacheInspection:
    closure: ClosureData
    sha256: str


def inspect_cache(root_fd: int, closure: ClosureData) -> CacheInspection:
    """Observe an exact independent inventory, without claiming upstream authenticity or exclusion."""
    require(type(closure) is ClosureData, "cache_closure")
    snapshot = scan(root_fd, CACHE_LIMITS)
    measured = tuple(file.binding for file in snapshot.files)
    expected = tuple(sorted((row.binding for row in closure.files), key=lambda row: row.path))
    require(measured == expected, "cache_files")
    return CacheInspection(closure, bindings_digest(measured))


@dataclass(frozen=True, slots=True)
class OutputInspection:
    """Consume the retained read-only stream inside its context; the caller still excludes writers."""
    profile: str
    jar: Binding
    classes: tuple[Binding, ...]
    classes_sha256: str
    cache_sha256: str
    stream: BinaryIO


@contextmanager
def inspect_output(root_fd: int, profile_id: str, cache: CacheInspection) -> Iterator[OutputInspection]:
    require(type(cache) is CacheInspection and type(cache.closure) is ClosureData, "output_cache")
    require(type(profile_id) is str and profile_id in ("f01", "f02", "f03", "f04"), "output_profile")
    selected = profile(profile_id)
    artifact = "primary-sqli" if selected.identifier in ("f01", "f02") else "jdbc-sqli"
    java = selected.files[3].path
    require(java.startswith("src/main/java/") and java.endswith(".java"), "output_profile_entry")
    entry_class = java[len("src/main/java/"):-len(".java")].replace("/", ".")
    source_pom = selected.files[2]
    pom = Binding("META-INF/maven/io.wakeio.fixtures/" + artifact + "/pom.xml", source_pom.size, source_pom.sha256)
    closure = cache.closure
    by_path = {row.binding.path: row.binding for row in closure.files}
    runtime = tuple(Binding("BOOT-INF/lib/" + PurePosixPath(path).name, by_path[path].bytes, by_path[path].sha256)
                    for path in closure.runtime)
    policy = JarPolicy(artifact, entry_class, pom, runtime, closure.loader)
    snapshot = scan(root_fd, OUTPUT_LIMITS)
    candidates = [file for file in snapshot.files
                  if "/" not in file.binding.path and file.binding.path.endswith(".jar")]
    require(len(candidates) == 1 and candidates[0].binding.path == artifact + "-1.0.0.jar", "output_jar_selection")
    candidate = candidates[0]
    require(0 < candidate.binding.bytes <= MAX_JAR, "output_jar_bound")
    with snapshot.open(candidate) as stream:
        classes = inspect(stream.fileno(), snapshot, policy)
        snapshot.check()
        stream.seek(0)
        yield OutputInspection(profile_id, candidate.binding, classes, bindings_digest(classes), cache.sha256, stream)
        snapshot.check()
