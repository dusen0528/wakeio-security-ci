"""Fixed Boot layout inspection of inert bytes, never bytecode execution or build authority."""
import hashlib
import re
from bisect import bisect_left
from dataclasses import dataclass
from typing import Final

from output_files import Binding, File, MAX_METADATA, OutputError, Snapshot, relative_path, require
from output_zip import Compression, Member, chunks, members

CLASSES: Final = "BOOT-INF/classes/"
LIB: Final = "BOOT-INF/lib/"
LAUNCHER: Final = "org.springframework.boot.loader.launch.JarLauncher"
MANIFEST: Final = "META-INF/MANIFEST.MF"
CLASSPATH: Final = "BOOT-INF/classpath.idx"
LAYERS: Final = "BOOT-INF/layers.idx"


@dataclass(frozen=True, slots=True)
class JarPolicy:
    artifact: str
    entry_class: str
    pom: Binding
    runtime: tuple[Binding, ...]
    loader: tuple[Binding, ...]

    @property
    def maven(self) -> str:
        return "META-INF/maven/io.wakeio.fixtures/" + self.artifact + "/"


def _body(fd: int, member: Member, bound: int) -> bytes:
    require(member.size <= bound, "jar_metadata_bound")
    return b"".join(chunks(fd, member))


def _text(body: bytes) -> str:
    try:
        return body.decode("utf-8", "strict")
    except UnicodeError as error:
        raise OutputError("jar_text") from error


def _lines(body: bytes) -> list[str]:
    """Only natural CR/LF boundaries create metadata records; other separators remain content."""
    text = _text(body).replace("\r\n", "\n").replace("\r", "\n")
    return text.removesuffix("\n").split("\n") if text else []


def _manifest(body: bytes, policy: JarPolicy) -> None:
    normalized = body.replace(b"\r\n", b"\n")
    require(b"\r" not in normalized and normalized.endswith(b"\n\n"), "jar_manifest")
    fields: list[bytes] = []
    for line in normalized[:-2].split(b"\n"):
        require(0 < len(line) <= 72, "jar_manifest")
        if line.startswith(b" "):
            require(bool(fields), "jar_manifest")
            fields[-1] += line[1:]
        else:
            fields.append(line)
    required = {"manifest-version": "1.0", "main-class": LAUNCHER, "start-class": policy.entry_class,
                "spring-boot-version": "4.1.2", "spring-boot-classes": CLASSES, "spring-boot-lib": LIB,
                "spring-boot-classpath-index": CLASSPATH, "spring-boot-layers-index": LAYERS}
    optional = {"build-jdk-spec": "21", "implementation-title": policy.artifact, "implementation-version": "1.0.0"}
    parsed: dict[str, str] = {}
    for field in fields:
        name, separator, value = field.partition(b": ")
        require(separator == b": " and re.fullmatch(rb"[A-Za-z0-9][A-Za-z0-9_-]{0,69}", name) is not None,
                "jar_manifest")
        key = name.decode("ascii").lower()
        text = _text(value)
        require(key not in parsed and all(ord(char) >= 32 and ord(char) != 127 for char in text), "jar_manifest")
        require(key in required or key in optional or key == "created-by", "jar_manifest_attribute")
        if key == "created-by":
            require(0 < len(value) <= 512, "jar_manifest_attribute")
        elif key in optional:
            require(text == optional[key], "jar_manifest_attribute")
        parsed[key] = text
    require(bool(parsed) and next(iter(parsed)) == "manifest-version"
            and all(parsed.get(key) == value for key, value in required.items()), "jar_manifest")


def _properties(body: bytes, artifact: str) -> None:
    parsed: dict[str, str] = {}
    for line in _lines(body):
        require(len(line) <= 4096, "jar_properties")
        if not line or line.startswith(("#", "!")):
            continue
        key, separator, value = line.partition("=")
        require(separator == "=" and key not in parsed, "jar_properties")
        parsed[key] = value
    require(parsed == {"groupId": "io.wakeio.fixtures", "artifactId": artifact, "version": "1.0.0"}, "jar_properties")


def _layers(body: bytes, names: tuple[str, ...]) -> None:
    expected = ("dependencies", "spring-boot-loader", "snapshot-dependencies", "application")
    layer = -1
    assigned: set[str] = set()
    for line in _lines(body):
        header = re.fullmatch(r'- "([a-z-]+)":', line)
        if header is not None:
            layer += 1
            require(layer < len(expected) and header[1] == expected[layer], "jar_layers")
            continue
        entry = re.fullmatch(r'  - "([^"\\]+)"', line)
        if layer < 0 or entry is None:
            raise OutputError("jar_layers")
        reference = entry[1]
        directory = reference.endswith("/")
        relative_path(reference[:-1] if directory else reference)
        start = bisect_left(names, reference)
        matched = 0
        for index in range(start, len(names)):
            name = names[index]
            if not (name.startswith(reference) if directory else name == reference):
                break
            require(name not in assigned, "jar_layer_overlap")
            assigned.add(name)
            matched += 1
        require(matched > 0, "jar_layers")
    require(layer == len(expected) - 1 and assigned == set(names), "jar_layer_coverage")


def _matches(fd: int, member: Member, expected: Binding) -> None:
    require(member.size == expected.bytes, "jar_binding_length")
    digest = hashlib.sha256()
    for chunk in chunks(fd, member):
        digest.update(chunk)
    require(digest.hexdigest() == expected.sha256, "jar_binding_digest")


def _compare(fd: int, member: Member, snapshot: Snapshot, file: File) -> Binding:
    require(member.size == file.binding.bytes, "jar_class_length")
    digest = hashlib.sha256()
    with snapshot.open(file) as stream:
        for chunk in chunks(fd, member):
            independently_read = stream.read(len(chunk))
            require(chunk == independently_read, "jar_class_bytes")
            digest.update(chunk)
        require(stream.read(1) == b"", "jar_class_length")
    return Binding(member.path[len(CLASSES):], member.size, digest.hexdigest())


def inspect(fd: int, snapshot: Snapshot, policy: JarPolicy) -> tuple[Binding, ...]:
    records = members(fd)
    regular = {member.path: member for member in records if not member.directory}
    classes = {CLASSES + file.binding.path[len("classes/"):]: file for file in snapshot.files
               if file.binding.path.startswith("classes/")}
    require(0 < len(classes) <= 4096 and sum(file.binding.bytes for file in classes.values()) <= 128 * 1024 * 1024,
            "jar_classes_bound")
    require(CLASSES + policy.entry_class.replace(".", "/") + ".class" in classes, "jar_entry_class")
    runtime = {row.path: row for row in policy.runtime}
    loader = {row.path: row for row in policy.loader}
    metadata = {MANIFEST, CLASSPATH, LAYERS, policy.maven + "pom.xml", policy.maven + "pom.properties"}
    expected = set(classes) | set(runtime) | set(loader) | metadata
    require(len(expected) == len(classes) + len(runtime) + len(loader) + len(metadata)
            and set(regular) == expected, "jar_members")
    names = tuple(sorted(expected))
    require(sum(regular[path].size for path in metadata | set(loader)) <= MAX_METADATA, "jar_metadata_bound")
    require(sum(row.bytes for row in policy.runtime) <= 64 * 1024 * 1024, "jar_runtime_bound")
    for member in records:
        if member.directory:
            prefix = member.path + "/"
            index = bisect_left(names, prefix)
            require(index < len(names) and names[index].startswith(prefix), "jar_directory")
            for chunk in chunks(fd, member):
                require(not chunk, "jar_directory")
    _manifest(_body(fd, regular[MANIFEST], 65536), policy)
    _properties(_body(fd, regular[policy.maven + "pom.properties"], 65536), policy.artifact)
    _matches(fd, regular[policy.maven + "pom.xml"], policy.pom)
    classpath = "".join('- "' + path + '"\n' for path in sorted(runtime)).encode("utf-8")
    require(_body(fd, regular[CLASSPATH], MAX_METADATA) == classpath, "jar_classpath")
    _layers(_body(fd, regular[LAYERS], MAX_METADATA), names)
    for path, row in runtime.items():
        require(regular[path].method == Compression.STORED, "jar_runtime_compression")
        _matches(fd, regular[path], row)
    for path, row in loader.items():
        _matches(fd, regular[path], row)
    return tuple(_compare(fd, regular[path], snapshot, classes[path]) for path in sorted(classes))
