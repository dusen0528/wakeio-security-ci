"""Protocol v1: bounded stdin job -> metadata-only JSON on stdout.
No caller URL, schema, credentials, file paths, or executable code is accepted.
"""
import hashlib
import importlib.metadata
import json
from pathlib import Path
import platform
import socket
import sys
import time


def main():
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError()
    job = json.loads(raw)
    keys = {"version", "environment", "fixture", "operations", "maxRequests", "timeoutMs",
            "maxBodyBytes", "maxTotalBytes", "seed", "replayQuantities"}
    if type(job) is not dict or set(job) != keys or type(job["version"]) is not int or job["version"] != 1:
        raise ValueError()
    if job["environment"] != "staging" or job["fixture"] not in ("broken", "fixed", "oversized", "slow"):
        raise ValueError()
    if job["operations"] != ["readItems"]:
        raise ValueError()
    for key, cap in (("maxRequests", 64), ("timeoutMs", 120000), ("maxBodyBytes", 2097152),
                     ("maxTotalBytes", 10485760), ("seed", 2147483647)):
        if type(job[key]) is not int or not 1 <= job[key] <= cap:
            raise ValueError()
    replay = job["replayQuantities"]
    if replay is not None and (type(replay) is not list or len(replay) != job["maxRequests"] or
                               any(type(q) is not int or not 1 <= q <= 20 for q in replay)):
        raise ValueError()
    # Trusted fixture only. OS/container egress enforcement is still needed for arbitrary code.
    def no_network(*args, **kwargs):
        raise RuntimeError("network_disabled")
    socket.socket.connect = no_network
    socket.socket.connect_ex = no_network
    socket.create_connection = no_network
    import schemathesis
    from hypothesis import given, seed, settings, Phase
    from schemathesis.checks import not_a_server_error
    from schemathesis.specs.openapi.checks import response_schema_conformance
    from schemathesis.core.failures import FailureGroup, ServerError
    from schemathesis.openapi.checks import JsonSchemaError
    from werkzeug.wrappers import Response

    data = Path(__file__).with_name("openapi.json").read_bytes()
    schema = schemathesis.openapi.from_dict(json.loads(data))
    operation = schema["/items"]["GET"]
    deadline = time.monotonic() + job["timeoutMs"] / 1000
    count, total, records, reason = 0, 0, [], "complete"

    class StopRun(Exception):
        pass

    def app(environ, start_response):
        nonlocal count, total, reason
        if reason != "complete":
            raise StopRun()
        if time.monotonic() >= deadline:
            reason = "timeout"
            raise StopRun()
        if count >= job["maxRequests"]:
            reason = "request_limit"
            raise StopRun()
        if environ["REQUEST_METHOD"] != "GET" or environ["PATH_INFO"] != "/items":
            raise ValueError()
        count += 1
        if job["fixture"] == "slow":
            time.sleep(5)
        body = json.dumps({"count": "synthetic-secret-canary" if job["fixture"] == "broken" else 1,
                           "secret": "synthetic-secret-canary"}).encode()
        if job["fixture"] == "oversized":
            body = b"x" * (job["maxBodyBytes"] + 1)
        if len(body) > job["maxBodyBytes"] or total + len(body) > job["maxTotalBytes"]:
            reason = "body_limit"
            raise StopRun()
        total += len(body)
        return Response(body, content_type="application/json")(environ, start_response)

    def check(case):
        nonlocal reason
        quantity = case.query["quantity"]
        if type(quantity) is not int or not 1 <= quantity <= 20:
            raise ValueError()
        response = case.call(app=app)
        if time.monotonic() >= deadline:
            reason = "timeout"
            raise StopRun()
        failures = []
        try:
            case.validate_response(response, checks=[not_a_server_error, response_schema_conformance])
        except FailureGroup as group:
            for failure in group.exceptions:
                # Project only trusted structural metadata. Never messages,
                # exception strings, bodies, headers, arbitrary paths or cURL.
                if isinstance(failure, JsonSchemaError):
                    if (failure.schema_path == ["properties", "count", "type"] and
                            failure.instance_path == ["count"] and type(failure.instance) is str):
                        failures.append({"rule": "response_schema_conformance", "kind": "type_mismatch",
                                         "instancePointer": "/count", "expected": "integer", "actualType": "string"})
                    else:
                        failures.append({"rule": "response_schema_conformance", "kind": "schema_violation",
                                         "instancePointer": "/", "expected": "schema_conformant"})
                elif isinstance(failure, ServerError):
                    failures.append({"rule": "not_a_server_error", "kind": "server_error",
                                     "instancePointer": "/", "expected": "status_below_500"})
                else:
                    raise ValueError()  # Unknown engine failure cannot silently become a known contract failure.
        records.append({"operation": "readItems", "method": "GET", "path": "/items",
                        "ordinal": len(records) + 1, "status": response.status_code,
                        "check": "response_contract" if failures else "passed",
                        "input": {"quantity": quantity, "token": "[REDACTED]",
                                  "fingerprint": hashlib.sha256(json.dumps(
                                      {"quantity": quantity}, sort_keys=True,
                                      separators=(",", ":")).encode()).hexdigest()},
                        "failures": failures})

    @seed(job["seed"])
    @settings(max_examples=job["maxRequests"], database=None, deadline=None, phases=[Phase.generate])
    @given(case=operation.as_strategy())
    def generate(case):
        check(case)
    try:
        if replay is None:
            generate()
        else:
            for quantity in replay:
                check(operation.Case(query={"quantity": quantity, "token": "synthetic-secret-canary"}))
    except StopRun:
        pass
    return {"version": 1, "status": "completed" if reason == "complete" else "partial",
            "reason": reason, "requestCount": count, "bytesInspected": total,
            "schemaSha256": hashlib.sha256(data).hexdigest(),
            "workerSha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "dependencyLockSha256": hashlib.sha256(Path(__file__).with_name("requirements.lock.txt").read_bytes()).hexdigest(),
            "engineVersion": importlib.metadata.version("schemathesis"),
            "runtime": {"python": platform.python_version(), "hypothesis": importlib.metadata.version("hypothesis"),
                        "jsonschema": importlib.metadata.version("jsonschema"),
                        "werkzeug": importlib.metadata.version("werkzeug")}, "records": records}


if __name__ == "__main__":
    try:
        result = main()
    except Exception:
        result = {"version": 1, "status": "error", "reason": "worker_error"}
    sys.stdout.write(json.dumps(result, separators=(",", ":")))
