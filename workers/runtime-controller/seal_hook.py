"""M1 InfoFD v3 parser adapted to private typed plans and the real transaction."""
import hashlib
import re
import urllib.parse

from seal_types import BASE, HOOK, Package, require


def hook_config(lines: list[str]) -> tuple[tuple[str, str], ...]:
    result = []
    for line in lines:
        key, separator, value = line.partition("=")
        require(separator == "=" and bool(key), "hook_config_field")
        fields = []
        for field in (key, value):
            require(re.fullmatch(r"(?:[^%]|%[0-9a-f]{2})*", field) is not None, "hook_escape")
            decoded = urllib.parse.unquote_to_bytes(field).decode("ascii")
            require(len(decoded) <= 4096 and re.fullmatch(r"[\x20-\x7e]*", decoded) is not None,
                    "hook_config_ascii")
            fields.append(decoded)
        require(re.fullmatch(r"[A-Za-z0-9:/_.+-]{1,256}", fields[0]) is not None, "hook_config_key")
        result.append((fields[0].lower(), fields[1]))
    return tuple(result)


def configuration(actual: tuple[tuple[str, str], ...], expected: dict[str, str]) -> None:
    required = {key.lower(): value for key, value in expected.items()}
    required.update({"apt::get::download": "false", "dpkg::pre-install-pkgs::": HOOK})
    # APT's list format has a trailing ::. Scalar duplicates are forbidden.
    for key, value in required.items():
        # SendPkgsInfo omits configuration nodes whose values are empty.
        require([v for k, v in actual if k == key] == ([value] if value else []), "hook_option:" + key)
    allowed = set(required) | {"dpkg", "dpkg::pre-install-pkgs", "apt::keep-fds",
                               "dpkg::tools", "dpkg::tools::options",
                               "dpkg::tools::options::" + HOOK.lower()}
    for key, value in actual:
        if key.startswith(("dpkg", "apt::update", "apt::keep-fds")):
            require(key in allowed, "hook_extra_execution_option")
        if key in allowed and key not in required:
            require(value == "", "hook_container_value")
        if key.startswith(("dir::", "acquire::")) and key not in required:
            # These defaults are inert or part of the native verified APT installation.
            safe = ("dir", "dir::bin", "dir::bin::methods", "dir::bin::dpkg", "dir::bin::apt-key",
                    "dir::bin::solvers", "dir::bin::planners", "dir::state", "dir::cache", "dir::etc",
                    "dir::log::terminal", "dir::log::history", "dir::log::planner",
                    "acquire", "acquire::https", "acquire::http", "acquire::indexTargets".lower())
            # Native APT derives these index/codec descriptors from its bound
            # binary. They cannot select hooks, sources, proxies or dpkg argv.
            generated = ("acquire::indextargets::", "acquire::compressiontypes::")
            require(key in safe or key.startswith(generated), "hook_extra_option")


def validate_install_hook(payload: bytes, plan: tuple[Package, ...], options: dict[str, str]) -> str:
    require(0 < len(payload) <= 65536, "hook_bound")
    text = payload.decode("ascii")
    require(re.fullmatch(r"[\x20-\x7e\n]+", text) is not None and text.endswith("\n"), "hook_ascii")
    lines = text[:-1].split("\n")
    require(lines[0] == "VERSION 3" and "" in lines[1:], "hook_version")
    end = lines.index("", 1)
    configuration(hook_config(lines[1:end]), options)
    expected = {p.name: p for p in plan}
    require(len(expected) == len(plan) and 4 <= len(plan) <= 48, "hook_plan")
    seen = set()
    for line in lines[end + 1:]:
        fields = line.split(" ")
        require(len(fields) == 9 and all(fields), "hook_record")
        name, direction, action = fields[0], fields[4], fields[8]
        require(name in expected, "hook_extra_package")
        package = expected[name]
        require(tuple(fields[1:4]) == (package.old.version, package.old.arch, package.old.multi), "hook_old")
        require(tuple(fields[5:8]) == (package.new.version, package.new.arch, package.new.multi), "hook_new")
        require(direction == package.direction and direction in ("<", "="), "hook_direction")
        kind = "configure" if action == "**CONFIGURE**" else "unpack"
        require(kind == "configure" or action == BASE + "/archives/" + package.file, "hook_deb")
        require((name, kind) not in seen, "hook_duplicate")
        seen.add((name, kind))
    require(seen == {(p.name, kind) for p in plan for kind in ("unpack", "configure")}, "hook_missing")
    return hashlib.sha256(payload).hexdigest()
