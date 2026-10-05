#!/usr/bin/env python3
"""Provider protocol double. No model requests, no credentials persisted."""
import json
import os
import pathlib
import sys

args = sys.argv[1:]
if "--version" in args:
    print("test-provider 1.0.0")
elif "--help" in args:
    print("--ignore-user-config --ignore-rules --output-schema --json --disable --bare --tools --safe-mode --strict-mcp-config --json-schema --max-budget-usd")
else:
    if os.environ.get("WAKEIO_TEST_SECRET_CANARY"):
        sys.exit(77)
    if "exec" in args:
        required = ["--ignore-user-config", "--ignore-rules", "--ephemeral", "--sandbox", "read-only", "--disable", "shell_tool"]
        if not os.environ.get("CODEX_API_KEY") or any(x not in args for x in required):
            sys.exit(78)
    else:
        required = ["--bare", "--safe-mode", "--tools", "", "--strict-mcp-config", "--disable-slash-commands", "--no-session-persistence"]
        if not os.environ.get("ANTHROPIC_API_KEY") or any(x not in args for x in required):
            sys.exit(78)
    job = json.load(sys.stdin)
    result = {"version": 1, "replacements": [{"path": "query.py", "beforeSha256": job["files"][0]["sha256"],
        "content": 'def lookup(db, name):\n    return db.execute("SELECT name FROM users WHERE name = ?", (name,)).fetchall()\n'}]}
    if "exec" in args:
        pathlib.Path(args[args.index("--output-last-message") + 1]).write_text(json.dumps(result))
        print(json.dumps({"type": "item.completed", "item": {"type": "agent_message", "text": json.dumps(result)}}))
    else:
        print(json.dumps({"type": "result", "subtype": "success", "is_error": False, "structured_output": result}))
