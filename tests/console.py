"""Verify MCP and the debuggee fixture can start without a console window."""

import ctypes
import json
from pathlib import Path
import queue
import struct
import subprocess
import sys
import threading


def check_fixture(fixture):
    image = Path(fixture).read_bytes()
    pe = struct.unpack_from("<I", image, 0x3C)[0]
    assert image[pe:pe + 4] == b"PE\0\0", "Fixture must be a Windows PE"
    # Subsystem is at offset 68 in the PE32 and PE32+ optional headers.
    subsystem = struct.unpack_from("<H", image, pe + 4 + 20 + 68)[0]
    assert subsystem == 2, "Launching the fixture would allocate a console"


def check(cli):
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    assert not kernel.GetConsoleCP(), "Probe needs a parent without a console"
    startup = subprocess.STARTUPINFO()
    startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startup.wShowWindow = subprocess.SW_HIDE
    with subprocess.Popen(
        [cli, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.PIPE, encoding="utf-8", startupinfo=startup,
    ) as mcp:
        try:
            request = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                  "params": {"protocolVersion": "2025-11-25"}})
            response = queue.Queue()
            threading.Thread(target=lambda: response.put(mcp.stdout.readline()),
                             daemon=True).start()
            mcp.stdin.write(request + "\n")
            mcp.stdin.flush()
            assert json.loads(response.get(timeout=5))["result"]["protocolVersion"] == "2025-11-25"
            # SW_HIDE keeps a regression from flashing during the test. If
            # the child allocated a console anyway, AttachConsole will succeed.
            if kernel.AttachConsole(mcp.pid):
                kernel.FreeConsole()
                raise AssertionError("Detached MCP unexpectedly allocated a console")
            assert ctypes.get_last_error() == 6, ctypes.WinError(ctypes.get_last_error())
            _, errors = mcp.communicate(timeout=5)
            assert mcp.returncode == 0, errors
        finally:
            if mcp.poll() is None:
                mcp.kill()


if __name__ == "__main__":
    if sys.argv[2] == "--detached":
        check(sys.argv[1])
    else:
        check_fixture(sys.argv[2])
        if sys.getwindowsversion().build < 26100:
            sys.exit(77)
        result = subprocess.run(
            [sys.executable, __file__, sys.argv[1], "--detached"],
            stdin=subprocess.DEVNULL, capture_output=True,
            creationflags=subprocess.DETACHED_PROCESS, timeout=15,
        )
        sys.stdout.buffer.write(result.stdout)
        sys.stderr.buffer.write(result.stderr)
        sys.exit(result.returncode)
