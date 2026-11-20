"""Run the installed binaries from a parent with no console."""

import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
from queue import Queue
import struct
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Thread
import time


def require_windows_subsystem(path):
    image = path.read_bytes()
    pe, = struct.unpack_from("<I", image, 0x3C)
    assert image[pe:pe + 4] == b"PE\0\0", path
    subsystem, = struct.unpack_from("<H", image, pe + 24 + 68)
    assert subsystem == 2, f"{path.name} can allocate a console at process creation"


def check_no_window(pid):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    if kernel.AttachConsole(pid):
        kernel.FreeConsole()
        raise AssertionError(f"Process {pid} owns a console")
    assert ctypes.get_last_error() == 6, ctypes.WinError(ctypes.get_last_error())

    user = ctypes.WinDLL("user32", use_last_error=True)
    callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    user.EnumWindows.argtypes = (callback_type, wintypes.LPARAM)
    user.GetWindowThreadProcessId.argtypes = (wintypes.HWND, ctypes.POINTER(wintypes.DWORD))
    user.IsWindowVisible.argtypes = (wintypes.HWND,)
    visible = []

    @callback_type
    def collect(window, _):
        owner = wintypes.DWORD()
        user.GetWindowThreadProcessId(window, ctypes.byref(owner))
        if owner.value == pid and user.IsWindowVisible(window):
            visible.append(window)
        return True

    assert user.EnumWindows(collect, 0), ctypes.WinError(ctypes.get_last_error())
    assert not visible, f"Process {pid} owns visible windows: {visible}"


def wait_for_session(cli, debugger):
    deadline = time.monotonic() + 12
    while time.monotonic() < deadline and debugger.poll() is None:
        sessions = cli("sessions")["sessions"]
        for session in sessions:
            if session["pid"] == debugger.pid:
                status = cli("status", "--session", session["session"])
                if status["state"] == "paused" and status["debuggee_pid"]:
                    return session["session"], status["debuggee_pid"]
        time.sleep(0.05)
    raise AssertionError("The headless debugger did not pause the fixture")


def check_mcp(cli, session):
    # Exercise a normal GUI-style spawn with inherited pipes and no creation flags.
    with subprocess.Popen([cli, "mcp", "--compact", "--session", session],
                          stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                          stderr=subprocess.PIPE, encoding="utf8") as process:
        lines = Queue()

        def read_responses():
            for line in process.stdout:
                lines.put(line)

        Thread(target=read_responses, daemon=True).start()

        def send(method, params=None, request_id=None):
            message = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                message["params"] = params
            if request_id is not None:
                message["id"] = request_id
            process.stdin.write(json.dumps(message) + "\n")
            process.stdin.flush()
            if request_id is not None:
                reply = json.loads(lines.get(timeout=8))
                assert reply["id"] == request_id, reply
                return reply["result"]

        try:
            send("initialize", {"protocolVersion": "2025-11-25"}, 1)
            check_no_window(process.pid)
            send("notifications/initialized")
            reply = send("tools/call", {"name": "x64dbgsql_query", "arguments": {
                "sql": "SELECT 42"}}, 2)
            assert reply["structuredContent"]["rows"] == [[{"int64": "42"}]], reply
            check_no_window(process.pid)
            process.stdin.close()
            assert process.wait(timeout=5) == 0, process.stderr.read()
        finally:
            if process.poll() is None:
                process.kill()


def probe(cli_path, debugger_path, plugin, fixture):
    assert not ctypes.windll.kernel32.GetConsoleCP(), "Probe parent has a console"

    def cli(*args):
        response = subprocess.run([cli_path, *args], capture_output=True,
                                  encoding="utf8", timeout=10, check=True)
        assert not response.stderr, response.stderr
        value = json.loads(response.stdout)
        assert value["ok"], value
        return value

    with TemporaryDirectory(prefix="x64dbgSQL windowless ") as directory:
        (Path(directory) / "headless.ini").write_text(
            "[Events]\nEntryBreakpoint=0\nSystemBreakpoint=1\n", encoding="ascii")
        with subprocess.Popen([debugger_path, "-userdir", directory, "-plugin", plugin, fixture],
                              cwd=debugger_path.parent, stdin=subprocess.PIPE,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              creationflags=subprocess.DETACHED_PROCESS) as debugger:
            try:
                session, debuggee = wait_for_session(cli, debugger)
                check_no_window(debugger.pid)
                check_no_window(debuggee)
                result = cli("query", "--json", "--session", session, "-q", "SELECT 17")
                assert result["rows"] == [[{"int64": "17"}]], result
                check_mcp(cli_path, session)
                check_no_window(debugger.pid)
                check_no_window(debuggee)
            finally:
                try:
                    debugger.communicate(b"exit\n", timeout=6)
                except subprocess.TimeoutExpired:
                    debugger.kill()
                    debugger.wait(timeout=5)


if __name__ == "__main__":
    if sys.argv[1] == "--probe":
        probe(*map(Path, sys.argv[2:]))
    else:
        inputs = [Path(value).resolve(strict=True) for value in sys.argv[1:]]
        require_windows_subsystem(inputs[0])
        require_windows_subsystem(inputs[3])
        result = subprocess.run([sys.executable, "-B", __file__, "--probe", *inputs],
                                stdin=subprocess.DEVNULL, capture_output=True,
                                timeout=35, creationflags=subprocess.DETACHED_PROCESS)
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        sys.exit(result.returncode)
