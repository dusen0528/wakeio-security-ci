"""Trusted SQL-injection regression/control for examples/repair-query.py only.

Keep outside the target snapshot; review and pin its SHA-256 in policy.
Exit 10 is exclusively the demonstrated security assertion failure, not setup failure.
"""
import hashlib
import importlib.util
import json
import pathlib
import sqlite3
import subprocess
import sys

# The target never shares the oracle's Python objects, stdout, or database.
# SQL is observed/executed by this trusted parent, not by model-controlled code.
def worker():
    spec = importlib.util.spec_from_file_location("target_query", pathlib.Path(sys.argv[2]) / "query.py")
    target = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(target)

    class Cursor:
        def __init__(self, rows):
            self.rows = rows

        def fetchall(self):
            return [tuple(row) for row in self.rows]

    class Database:
        def execute(self, sql, parameters=()):
            print(json.dumps({"op": "execute", "sql": sql, "parameters": parameters}), flush=True)
            return Cursor(json.loads(sys.stdin.readline())["rows"])

    rows = target.lookup(Database(), json.loads(sys.argv[3]))
    print(json.dumps({"op": "result", "rows": rows}), flush=True)


def observe(db, root, value):
    child = subprocess.Popen([sys.executable, "-I", __file__, "--target-worker", root, json.dumps(value)],
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                             text=True, env={})
    observed = []
    try:
        for _ in range(9):
            line = child.stdout.readline(65537)
            if not line or len(line) > 65536 or not line.endswith("\n"):
                raise ValueError("invalid protocol")
            message = json.loads(line)
            if not isinstance(message, dict):
                raise ValueError("invalid protocol")
            if message.get("op") == "execute" and set(message) == {"op", "sql", "parameters"}:
                if not isinstance(message["sql"], str) or not isinstance(message["parameters"], list):
                    raise ValueError("invalid query")
                rows = db.execute(message["sql"], message["parameters"]).fetchall()
                observed.append(rows)
                child.stdin.write(json.dumps({"rows": rows}) + "\n")
                child.stdin.flush()
            elif message.get("op") == "result" and set(message) == {"op", "rows"}:
                child.stdin.close()
                if child.wait(timeout=2) != 0 or child.stdout.read(1):
                    raise ValueError("invalid completion")
                return message["rows"], observed
            else:
                raise ValueError("invalid protocol")
        raise ValueError("query limit")
    finally:
        if child.poll() is None:
            child.kill()
        child.wait()
        if not child.stdin.closed:
            child.stdin.close()
        child.stdout.close()


if len(sys.argv) > 1 and sys.argv[1] == "--target-worker":
    try:
        worker()
        sys.exit(0)
    except Exception:
        sys.exit(20)

samples = {"normal": "alice", "attack": "' OR 1=1 --"}
fingerprint = hashlib.sha256(json.dumps(samples, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
try:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users (name TEXT)")
    db.executemany("INSERT INTO users VALUES (?)", [("alice",), ("bob",)])
    # Target queries may only select users.name, never attach databases or write files.
    db.set_authorizer(lambda action, table, column, database, trigger:
                      sqlite3.SQLITE_OK if action == sqlite3.SQLITE_SELECT or
                      (action == sqlite3.SQLITE_READ and table == "users" and column == "name") else sqlite3.SQLITE_DENY)
    result, trace = observe(db, sys.argv[1], samples["normal"])
    normal = result == [["alice"]] and bool(trace) and all(rows == [("alice",)] for rows in trace)
    result, trace = observe(db, sys.argv[1], samples["attack"])
    blocked = result == [] and all(rows == [] for rows in trace)
    result = {"version": 1, "inputFingerprint": fingerprint,
              "security": "passed" if blocked else "failed", "normal": "passed" if normal else "failed"}
    print(json.dumps(result))
    sys.exit(0 if blocked and normal else 10 if normal and not blocked else 20)
except Exception:
    # Never return setup/import/SQL errors as vulnerability reproduction.
    sys.exit(20)
