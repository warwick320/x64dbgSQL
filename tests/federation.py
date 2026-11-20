"""Exercise both analyzer HTTP contracts against a real, local x64dbg fixture."""

import argparse
import ctypes
import hashlib
import http.server
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import struct
import tempfile
import threading
import time


def wait_for(read, predicate):
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        value = read()
        if predicate(value):
            return value
        time.sleep(0.05)
    raise AssertionError(f"Timed out with {value!r}")


class Analyzer(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def handle(self):
        try:
            super().handle()
        except (BrokenPipeError, ConnectionResetError):
            # WinHTTP can reset a persistent connection on shutdown or timeout.
            pass

    def log_message(self, *_args):
        return

    def do_POST(self):
        if self.path != "/query" or self.headers.get("Authorization") != "Bearer test-fixture":
            self.send_error(401)
            return
        sql = self.rfile.read(int(self.headers["Content-Length"])).decode("utf8")
        owner = self.server
        owner.requests.append(sql)
        owner.connections.append(self.client_address)
        if "FROM binary WHERE" in sql:
            columns = ["key", "value"]
            rows = sorted(
                dict(
                    tool_name=owner.backend,
                    tool_version="fixture",
                    image_base=hex(owner.static_base),
                    bits=str(owner.bits),
                    sha256=owner.digest,
                    filename=owner.filename,
                    revision=str(owner.revision),
                ).items()
            )
        elif "FROM func_at(" in sql or "FROM function_chunks c" in sql:
            columns = ["entry", "lo", "hi", "name"]
            # The resolved IP lies in a disjoint chunk owned by an earlier entry.
            rows = [[str(owner.point - 0x20), str(owner.point), str(owner.point + 4), "fixture_marker"]]
            owner.revision += int(owner.change_during_read)
        elif "FROM sqlite_master" in sql:
            columns, rows = ["name", "type"], [["pseudocode", "table"]]
        elif sql == 'SELECT "name" FROM "batch_labels" LIMIT 2':
            delay = owner.batch_read_delay
            if delay:
                time.sleep(delay)
            columns, rows = ["name"], [["fixture_label"], ["second_label"]]
            owner.revision += int(owner.change_during_read)
        elif sql == 'SELECT "text" FROM "batch_large" LIMIT 2':
            columns, rows = ["text"], [["x" * 100_000]]
        elif sql.startswith('SELECT "text" FROM "pseudocode"'):
            address = owner.point - 0x20
            if f'"func_addr">={address} AND "func_addr"<{address+1}' not in sql:
                self.send_error(400)
                return
            columns, rows = ["text"], [["fixture decompiler text"]]
        elif sql.startswith('SELECT * FROM "pseudocode" WHERE "func_addr"='):
            selected = int(sql.split('=', 1)[1].split(' ', 1)[0])
            if selected != owner.point - 0x20:
                self.send_error(400)
                return
            columns, rows = ["func_addr", "text"], [[owner.point - 0x20, "fixture decompiler text"]]
        else:
            self.send_error(400)
            return
        statement = {"success": True, "columns": columns, "rows": rows, "row_count": len(rows)}
        if owner.partial and "FROM function_chunks c" in sql:
            statement["partial"] = True
        document = (
            statement
            if owner.backend == "idasql"
            else {"success": True, "statement_count": 1, "results": [statement]}
        )
        body = json.dumps(document).encode("utf8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def verify_static_batch(cli, connection, server, env):
    def call(name, arguments):
        messages = [
            {"method": "initialize", "id": 1, "params": {"protocolVersion": "2025-11-25"}},
            {"method": "notifications/initialized"},
            {"method": "tools/call", "id": 2, "params": {"name": name, "arguments": arguments}},
        ]
        mcp = subprocess.run(
            [cli, "mcp", "--compact", *connection],
            input="".join(json.dumps(dict(message, jsonrpc="2.0")) + "\n" for message in messages),
            env=env, capture_output=True, text=True, encoding="utf8", timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW, check=True,
        )
        return json.loads(mcp.stdout.splitlines()[-1])

    def batch(arguments):
        response = call("x64dbgsql_static_read_batch", arguments)
        assert "result" in response, response
        result = response["result"]
        content = result["structuredContent"]
        assert result["isError"] == (not content["ok"]), result
        return content

    address = server.point - 0x20
    projected = {
        "table": "pseudocode", "where": {"func_addr": str(address)}, "columns": ["text"],
        "range": {"column": "func_addr", "start": str(address), "end": str(address + 1)},
    }
    labels = {"table": "batch_labels", "columns": ["name"], "max_rows": 1}
    reads = [projected, labels, projected, labels]
    server.requests.clear()
    singles = [
        call("x64dbgsql_static_read", read)["result"]["structuredContent"] for read in reads
    ]
    single_requests = server.requests[:]
    assert len(single_requests) == 12, single_requests
    assert all(result["ok"] for result in singles), singles
    assert singles[1]["rows"] == [["fixture_label"]] and singles[1]["truncated"], singles
    server.requests.clear()
    server.connections.clear()
    grouped = batch({"reads": reads})
    assert grouped == {"ok": True, "results": singles}, grouped
    expected_requests = [single_requests[0], *single_requests[1::3], single_requests[-1]]
    assert len(server.requests) == 6 and server.requests == expected_requests, server.requests
    assert len(set(server.connections)) == 1, server.connections
    print(f"{server.backend}: four single native reads used 12 HTTP requests, batch used 6")

    server.requests.clear()
    assert len(batch({"reads": [labels] * 32})["results"]) == 32
    assert len(server.requests) == 34, server.requests

    invalid_inputs = [
        {"reads": []},
        {"reads": [labels] * 33},
        {"reads": [labels, None]},
        {"reads": [labels], "sql": "SELECT 1"},
        {"reads": [labels], "timeout_ms": 15001},
        {"reads": [labels, dict(labels, sql="SELECT 1")]},
        {"reads": [labels, dict(labels, timeout_ms=100)]},
        {"reads": [labels, dict(labels, table="sqlite_master")]},
        {"reads": [labels, dict(labels, columns=["name", "NAME"])]},
        {"reads": [labels, dict(labels, columns=["COUNT(*)"])]},
        {"reads": [labels, dict(labels, columns=["name"] * 33)]},
        {"reads": [labels, dict(labels, columns="name")]},
        {"reads": [labels, dict(labels, where={"name": 42})]},
        {"reads": [labels, dict(labels, max_rows=201)]},
        {"reads": [labels, dict(labels, where={"name": "@function"})]},
        {"reads": [labels, dict(projected, range={"column": "func_addr", "start": "5", "end": "5"})]},
        {"reads": [labels, dict(projected, range=dict(projected["range"], extra="1"))]},
        {"reads": [labels, dict(projected, range=dict(projected["range"], start=address))]},
    ]
    server.requests.clear()
    for arguments in invalid_inputs:
        result = batch(arguments)
        assert result["error"]["code"] == "E_INPUT" and "results" not in result, result
    assert not server.requests, server.requests

    failed = batch({"reads": [projected, {"table": "batch_missing"}, labels]})
    assert failed["error"]["code"] == "E_STATIC_QUERY" and "results" not in failed, failed
    assert len(server.requests) == 3, server.requests

    server.change_during_read = True
    try:
        changed = batch({"reads": [projected, labels]})
        assert changed["error"]["code"] == "E_STATIC_CHANGED" and "results" not in changed, changed
    finally:
        server.change_during_read = False

    large = {"table": "batch_large", "columns": ["text"], "max_rows": 1}
    result = batch({"reads": [large] * 2})
    assert result["ok"] and len(result["results"]) == 2
    oversized = batch({"reads": [large] * 3})
    assert oversized["error"]["code"] == "E_STATIC_LIMIT" and "results" not in oversized, oversized

    # Neither delayed read should consume the entire deadline on its own.
    server.batch_read_delay = 0.4
    try:
        expired = batch({"reads": [labels, labels], "timeout_ms": 650})
        assert expired["error"]["code"] == "E_TIMEOUT" and "results" not in expired, expired
    finally:
        server.batch_read_delay = 0


def int_cell(cell):
    return int(cell["int64"])


def verify_read_stream(session, query_once):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    create = kernel.CreateFileW
    create.argtypes = [
        ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
        ctypes.c_uint32, ctypes.c_uint32, ctypes.c_void_p,
    ]
    create.restype = ctypes.c_void_p
    name = rf"\\.\pipe\x64dbgsql-{session}-stream"
    handle = create(name, 0x100003, 0, None, 3, 0, None)
    if handle == ctypes.c_void_p(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    descriptor = msvcrt.open_osfhandle(handle, os.O_RDWR | os.O_BINARY)
    with os.fdopen(descriptor, "r+b", buffering=0) as pipe:
        def exact(length):
            reply = bytearray()
            while len(reply) < length:
                chunk = pipe.read(length - len(reply))
                if not chunk:
                    raise EOFError("The read stream closed")
                reply.extend(chunk)
            return reply

        def exchange(message, acknowledge=True):
            data = json.dumps(message).encode("utf8")
            pipe.write(struct.pack("<I", len(data)) + data)
            size, = struct.unpack("<I", exact(4))
            result = json.loads(exact(size))
            if acknowledge:
                pipe.write(b"\x01")
            return result

        assert exchange({"op": "hello", "version": 1}, False)["session"] == session
        assert exchange({"op": "schema", "table": "registers"})["ok"]
        response = exchange({"op": "query", "request_id": "stream-test", "sql": "SELECT 5"})
        assert response["rows"] == [[{"int64": "5"}]], response
        assert query_once()["rows"] == [[{"int64": "7"}]]
        response = exchange({"op": "status"})
        assert response["error"]["code"] == "E_PROTOCOL", response
        assert exchange({"op": "query", "request_id": "stream-again", "sql": "SELECT 8"})[
            "rows"] == [[{"int64": "8"}]]


def verify(args, process, env):
    def cli(*arguments):
        result = subprocess.run(
            [args.cli, *arguments],
            capture_output=True,
            text=True,
            encoding="utf8",
            env=env,
            timeout=20,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        try:
            return json.loads(result.stdout)
        except ValueError as error:
            raise AssertionError(result.stderr or result.stdout) from error

    session = wait_for(
        lambda: next(
            (r for r in cli("sessions").get("sessions", []) if r["pid"] == process.pid),
            None,
        ),
        bool,
    )
    base_args = ["--session", session["session"]]
    wait_for(lambda: cli("status", *base_args), lambda r: r.get("state") == "paused")
    verify_read_stream(session["session"],
                       lambda: cli("query", "--json", *base_args, "-q", "SELECT 7"))

    for operation, verb in [("breakpoint", "add"), ("control", "run")]:
        reply = cli(operation, verb, *base_args, "--reason", "federation fixture")
        assert reply["ok"], reply
        action = wait_for(
            lambda: cli("action", "status", reply["action_id"], *base_args),
            lambda value: value.get("status") not in (None, "accepted"),
        )
        assert action["status"] == "done", action

    def stop():
        return cli(
            "query", "--json", *base_args, "-q",
            "SELECT s.ip,m.base,m.name FROM session s JOIN modules m "
            "ON s.ip>=m.base AND s.ip-m.base<m.size "
            "WHERE m.name='x64dbgsql_fixture.exe'",
        )

    live = wait_for(stop, lambda r: r.get("row_count") == 1)
    ip, live_base, filename = live["rows"][0]
    ip, live_base = int_cell(ip), int_cell(live_base)
    digest = hashlib.sha256(Path(args.fixture).read_bytes()).hexdigest()
    if args.live_ghidra or args.live_ida:
        backend, url = ("ghidra", args.live_ghidra) if args.live_ghidra else ("ida", args.live_ida)
        connection = ["--static-provider", backend, "--static-url", url]
        info = cli("static", "info", *connection, "--timeout-ms", "15000")
        assert info["ok"] and info["program"]["sha256"] == digest, info
        static_base = info["program"]["image_base"]
        projected = cli(
            "static", "read", "funcs", *connection, "--timeout-ms", "15000",
            "--static-columns", "addr,name", "--static-range",
            f"addr={static_base}:{static_base + 0x100000}", "--max-rows", "4",
        )
        assert projected["ok"] and projected["columns"] == ["addr", "name"], projected
        assert 0 < projected["row_count"] <= 4, projected
        report = cli(
            "query", "--json", *base_args, *connection,
            "--timeout-ms", "15000", "--static-table", "pseudocode",
            "--static-where", "func_addr=@function",
            "-q", "SELECT c.static_function,c.runtime_addr,count(r.ordinal) "
                  "FROM static_stop_context c LEFT JOIN static_rows r ON r.backend=c.backend "
                  "GROUP BY c.static_function,c.runtime_addr",
        )
        assert report["ok"] and report["row_count"] == 1, report
        name, entry, rows = report["rows"][0]
        assert "fixture_marker" in name and int_cell(entry) == ip and int_cell(rows) >= 1, report
        print(json.dumps(report))
        return
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Analyzer)
    server.filename = filename
    server.digest = digest
    server.bits = 64 if session["arch"] == "x64" else 32
    server.static_base = 0x140000000 if server.bits == 64 else 0x400000
    if server.static_base == live_base:
        server.static_base += 0x100000
    server.point = server.static_base + ip - live_base
    server.revision = 1
    server.partial = False
    server.change_during_read = False
    server.requests = []
    server.connections = []
    server.batch_read_delay = 0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        for backend in ("ida", "ghidra"):
            server.backend = "idasql" if backend == "ida" else "ghidrasql"
            connection = [
                "--static-provider", backend, "--static-url",
                f"http://127.0.0.1:{server.server_port}",
            ]
            verify_static_batch(args.cli, connection, server, env)
            info = cli("static", "info", *connection)
            assert info["ok"] and info["program"]["sha256"] == digest, info
            catalog = cli("static", "catalog", *connection)
            assert catalog["ok"] and catalog["row_count"] == 1, catalog
            predicate = ["--static-where", f"func_addr={hex(server.point - 0x20)}"]
            native = cli("static", "read", "pseudocode", *connection, *predicate)
            assert native["ok"] and native["rows"][0][1] == "fixture decompiler text", native
            address = server.point - 0x20
            selection = [
                "--static-columns", "text", "--static-range",
                f"func_addr={address}:{address+1}",
            ]
            projected = cli("static", "read", "pseudocode", *connection, *predicate, *selection)
            assert projected["ok"] and projected["columns"] == ["text"], projected
            assert projected["rows"] == [["fixture decompiler text"]], projected
            invalid = cli("static", "read", "pseudocode", *connection,
                          "--static-range", "func_addr=5:5")
            assert invalid["error"]["code"] == "E_INPUT", invalid
            invalid = cli("static", "read", "pseudocode", *connection,
                          "--static-columns", "text,COUNT(*)")
            assert invalid["error"]["code"] == "E_INPUT", invalid
            combined = [
                "query", "--json", *connection, *base_args,
                "--static-table", "pseudocode", "--static-where", "func_addr=@function", "-q",
                "SELECT c.static_function,c.static_addr,c.runtime_addr,json_extract(r.data,'$.text') "
                "FROM static_stop_context c JOIN static_rows r ON r.backend=c.backend",
            ]
            report = cli(*combined)
            assert report["ok"] and report["row_count"] == 1, report
            projected = cli(*combined, *selection)
            assert projected["ok"] and projected["rows"] == report["rows"], projected
            name, original, rebased, text = report["rows"][0]
            assert (name, int_cell(original), int_cell(rebased), text) == (
                "fixture_marker", server.point - 0x20, ip - 0x20, "fixture decompiler text"
            ), report
            messages = [
                {"method": "initialize", "id": 1, "params": {"protocolVersion": "2025-11-25"}},
                {"method": "notifications/initialized"},
                {"method": "tools/list", "id": 2},
                {"method": "tools/call", "id": 3, "params": {
                    "name": "x64dbgsql_query", "arguments": {
                        "sql": "SELECT static_function FROM static_stop_context"
                    }
                }},
            ]
            mcp = subprocess.run(
                [args.cli, "mcp", *connection, *base_args, "--static-rva", "current"],
                input="".join(json.dumps(dict(message, jsonrpc="2.0")) + "\n" for message in messages),
                env=env, capture_output=True, text=True, encoding="utf8", timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW,
            )
            responses = {message["id"]: message for message in map(json.loads, mcp.stdout.splitlines())}
            tools = {tool["name"]: tool for tool in responses[2]["result"]["tools"]}
            assert set(tools) == {
                "x64dbgsql_query", "x64dbgsql_schema", "x64dbgsql_static_catalog",
                "x64dbgsql_static_read", "x64dbgsql_static_read_batch",
            }, responses
            batch_schema = tools["x64dbgsql_static_read_batch"]["inputSchema"]
            assert batch_schema["required"] == ["reads"] and not batch_schema["additionalProperties"]
            read_array = batch_schema["properties"]["reads"]
            assert (read_array["type"], read_array["minItems"], read_array["maxItems"]) == (
                "array", 1, 32
            )
            item = read_array["items"]
            assert item["required"] == ["table"] and not item["additionalProperties"]
            assert set(item["properties"]) == {"table", "where", "columns", "range", "max_rows"}
            assert item["properties"]["range"]["properties"]["start"]["type"] == "string"
            assert responses[3]["result"]["structuredContent"]["rows"] == [["fixture_marker"]], responses
            messages[-1]["params"] = {
                "name": "x64dbgsql_static_read",
                "arguments": {
                    "table": "pseudocode",
                    "where": {"func_addr": str(address)},
                    "columns": ["text"],
                    "range": {"column": "func_addr", "start": str(address),
                              "end": str(address + 1)},
                },
            }
            mcp = subprocess.run(
                [args.cli, "mcp", "--compact", *connection],
                input="".join(json.dumps(dict(message, jsonrpc="2.0")) + "\n" for message in messages),
                env=env, capture_output=True, text=True, encoding="utf8", timeout=20,
                creationflags=subprocess.CREATE_NO_WINDOW, check=True,
            )
            result = json.loads(mcp.stdout.splitlines()[-1])["result"]
            assert result["content"] == [{"type": "text", "text": "See structuredContent."}]
            reply = result["structuredContent"]
            assert reply["columns"] == ["text"] and reply["rows"] == [["fixture decompiler text"]], reply
            server.digest = "a" * 64
            mismatch = cli(*combined)
            assert mismatch["error"]["code"] == "E_STATIC_IDENTITY", mismatch
            server.digest = digest
            server.change_during_read = True
            changed = cli(*combined)
            assert changed["error"]["code"] == "E_STATIC_CHANGED", changed
            server.change_during_read = False
            if backend == "ghidra":
                server.partial = True
                partial = cli(*combined)
                assert partial["error"]["code"] == "E_STATIC_QUERY", partial
                server.partial = False
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def main():
    parser = argparse.ArgumentParser()
    for name in ("debugger", "cli", "plugin", "fixture"):
        parser.add_argument(f"--{name}", required=True)
    live = parser.add_mutually_exclusive_group()
    live.add_argument("--live-ghidra")
    live.add_argument("--live-ida")
    args = parser.parse_args()
    env = dict(os.environ, X64DBGSQL_FIXTURE=str(Path(args.fixture).resolve()))
    if not (args.live_ghidra or args.live_ida):
        env["X64DBGSQL_STATIC_TOKEN"] = "test-fixture"
    with tempfile.TemporaryDirectory(prefix="x64dbgSQL federation ") as home:
        (Path(home) / "headless.ini").write_text(
            "[Events]\nEntryBreakpoint=0\nSystemBreakpoint=1\n", encoding="ascii"
        )
        with tempfile.TemporaryFile() as log:
            process = subprocess.Popen(
                [args.debugger, "-userdir", home, "-plugin", args.plugin, args.fixture],
                cwd=Path(args.debugger).parent, env=env, stdin=subprocess.PIPE,
                stdout=log, stderr=log, creationflags=subprocess.CREATE_NO_WINDOW,
            )
            try:
                verify(args, process, env)
            except Exception:
                log.seek(0)
                print(log.read().decode("utf8", errors="replace")[-8000:])
                raise
            finally:
                try:
                    process.communicate(b"exit\n", timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.communicate()


if __name__ == "__main__":
    main()
