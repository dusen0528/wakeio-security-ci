#!/usr/bin/env python3
"""CLI boundary double, NOT a sandbox. Executes only our trusted test fixture."""
import json
import os
import subprocess
import sys

args = sys.argv[1:]
if args[:1] == ["--host"]:
    if args[1] != "unix:///tmp/wakeio-test-docker.sock" or "DOCKER_HOST" in os.environ:
        sys.exit(94)
    args = args[2:]
if args[:1] == ["info"]:
    print("27.0.0")
elif args[:2] == ["image", "inspect"]:
    print("sha256:" + "a" * 64)
elif args[:1] == ["rm"]:
    pass
elif args[:1] == ["run"]:
    required = ["--network=none", "--read-only", "--user=65534:65534", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--pids-limit=64", "--memory=256m", "--cpus=1", "--pull=never"]
    if any(flag not in args for flag in required):
        sys.exit(91)
    image = args.index("sha256:" + "a" * 64)
    command = args[image + 1:]
    mounts = {}
    for i, arg in enumerate(args):
        if arg == "--mount":
            fields = dict(part.split("=", 1) for part in args[i + 1].split(",") if "=" in part)
            mounts[fields["target"]] = fields["source"]
            if "readonly" not in args[i + 1] or fields["target"] not in ["/workspace", "/verifier"]:
                sys.exit(92)
    command = [mounts.get(value, value) if value in mounts else
               mounts["/verifier"] + "/check.py" if value == "/verifier/check.py" else value for value in command]
    command[0] = sys.executable
    result = subprocess.run(command, env={"PATH": os.environ.get("PATH", "")}, capture_output=True)
    sys.stdout.buffer.write(result.stdout)
    sys.exit(result.returncode)
else:
    sys.exit(93)
