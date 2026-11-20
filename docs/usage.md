# x64dbgSQL usage guide

## Headless sessions

Use `x64dbgsql-headless.exe` when a launcher has no terminal. The process reads and writes redirected streams, so capture its output or connect it to an MCP client. The terminal executable is `x64dbgsql.exe`.

The debugger host also needs to run headlessly if you want a session without a debugger window. Use `headless.exe` from the matching directory in the x64dbg release. This Python example starts a 64-bit session, waits for the plugin to register it, and prints a query result. Set the two paths before running it. For a 32-bit target, use `x32` and `x64dbgsql.dp32` with the same x64 client.

```python
import json
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import time

root = Path(r"C:\Tools\x64dbg\release")
target = Path(r"C:\Work\example.exe")
host = root / "x64" / "headless.exe"
plugin = root / "x64" / "plugins" / "x64dbgsql.dp64"
client = root / "x64dbgsql-headless.exe"

def cli(*args):
    result = subprocess.run(
        [client, *args], capture_output=True, check=True, encoding="utf-8", timeout=15,
    )
    return json.loads(result.stdout)

with TemporaryDirectory(prefix="x64dbgsql-session-") as settings:
    (Path(settings) / "headless.ini").write_text(
        "[Events]\nEntryBreakpoint=0\nSystemBreakpoint=1\n", encoding="ascii",
    )
    with subprocess.Popen(
        [host, "-userdir", settings, "-plugin", plugin, target],
        cwd=host.parent, creationflags=subprocess.DETACHED_PROCESS,
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    ) as debugger:
        try:
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline and debugger.poll() is None:
                for session in cli("sessions")["sessions"]:
                    if session["pid"] == debugger.pid:
                        session_id = session["session"]
                        state = cli("status", "--session", session_id)
                        if state["state"] == "paused" and state["debuggee_pid"]:
                            break
                else:
                    time.sleep(0.1)
                    continue
                break
            else:
                raise RuntimeError("The debugger did not publish a paused session")

            print(cli("query", "--json", "--session", session_id,
                      "-q", "SELECT * FROM stop_context")["rows"])
        finally:
            try:
                debugger.communicate(b"exit\n", timeout=5)
            except subprocess.TimeoutExpired:
                debugger.kill()
                debugger.wait()
```

The target program retains its own window behavior. A GUI target may still display its interface. For readable debugger logs, redirect the host's stdout and stderr to a log file.

## MCP

For clients that use an `mcpServers` configuration, add the following entry and set the executable path.

```json
{
  "mcpServers": {
    "x64dbgsql": {
      "command": "C:\\Tools\\x64dbg\\release\\x64dbgsql-headless.exe",
      "args": ["mcp", "--compact"]
    }
  }
}
```

The MCP endpoint uses stdio and offers read-only tools. Use `--compact` with clients that read `structuredContent`. For a specific session, add `"--session", "<session-id>"`. Keep the process running across repeated requests to reuse the read connection.

## Querying a session

Use `schema` to see the available tables. `register_context` maps register values to modules and memory regions, `image_layout` relates file sections to runtime mappings, and `stop_context` shows the current stop location. `call_stack` and `disassembly(addr,count)` require a paused target. `events` contains recent events and `event_spans` derives timing within a debugger generation.

```powershell
.\x64dbgsql.exe query -q 'SELECT name, value, module, rva FROM register_context'
.\x64dbgsql.exe query -q 'SELECT seq, type, elapsed_ms FROM event_spans ORDER BY seq DESC LIMIT 20'
.\x64dbgsql.exe query --json -f .\query.sql
```

JSON results encode SQLite integers as `{"int64":"..."}` and BLOBs as `{"blob_hex":"..."}`. Use `--max-rows` and `--timeout-ms` to bound a query. The `work` object reports provider reads and cache usage.

To compare two pauses in the same session and debugger generation, capture a checkpoint at each pause.

```powershell
.\x64dbgsql.exe checkpoint capture before.json --session $session
# Resume in the debugger, then pause again.
.\x64dbgsql.exe checkpoint capture after.json --session $session
.\x64dbgsql.exe checkpoint diff before.json after.json
```

GUI sessions can opt in to editing comments, labels, and bookmarks using the plugin menu or by setting `X64DBGSQL_ENABLE_ANNOTATIONS=1` before launching the debugger. Editing commands require an explicit session and reason.

## Static analysis

Connect to a running loopback endpoint from [IDASQL](https://github.com/allthingsida/idasql) or [GhidraSQL](https://github.com/0xeb/ghidrasql). The default ports are IDASQL `8080` and GhidraSQL `8081`. Use `--static-url` to select another loopback address, and `X64DBGSQL_STATIC_TOKEN` for an endpoint protected by a bearer token.

```powershell
.\x64dbgsql.exe static info --static-provider ida
.\x64dbgsql.exe static catalog --static-provider ghidra
.\x64dbgsql.exe static read binary --static-provider ida --static-columns key,value
.\x64dbgsql.exe query --static-provider ida --static-rva current -q 'SELECT * FROM static_stop_context'
```

For combined queries, open the same binary in both tools and pause inside the relevant module. The client checks the binary identity and maps the runtime address to the static image. Use `--static-module` to resolve an ambiguous module and `--static-range COLUMN=START:END` to select an inclusive start and exclusive end.

Add `--static-provider` to the MCP arguments to expose `x64dbgsql_static_catalog`, `x64dbgsql_static_read`, and `x64dbgsql_static_read_batch`. Group independent reads with the batch tool. It accepts 1–32 items under a shared timeout and a 256 KiB structured-result limit. It checks the reported program identity before and after the group.

## Unattended installation

Run setup against a writable debugger directory with the debugger closed. Each Windows user can manage one installer destination. Exit code zero indicates success. Use `/LOG="path"` to collect installation diagnostics if needed.

```powershell
$install = Start-Process -FilePath .\x64dbgsql-setup.exe -ArgumentList @(
    '/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/DIR="C:\Tools\x64dbg\release"'
) -Wait -PassThru
if ($install.ExitCode) { throw "Setup exited with code $($install.ExitCode)" }
```

Uninstall through **Installed apps**, or run the matching uninstaller from the `.x64dbgsql` directory using `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART`. Setup manages the client and plugin files it installs. Existing debugger executables and settings stay in the debugger directory.

Compare `Get-FileHash .\x64dbgsql-setup.exe -Algorithm SHA256` with `SHA256SUMS` from the release.

## Building release packages

After both Release builds and tests pass, run the packager. Use Inno Setup 6.7 or newer for the installer build.

```powershell
.\cmake\PackageWindows.ps1 -InnoCompiler 'C:\Program Files (x86)\Inno Setup 6\ISCC.exe'
```

Use `-CMake <path>` when CMake is available only through Visual Studio, and `-Destination <path>` to change the output directory. The default is `out/packages`. The runtime ZIP and installer contain the product binaries and license notices. Build the fixture from source to run the integration tests.

```powershell
python -B tests/installer.py out/packages/x64dbgsql-setup.exe .deps/debugger/release
```

Run the installer test under a user profile without an existing installer-managed copy. It uses temporary debugger folders and verifies installation, upgrade, collision handling, and removal.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| No x64dbgSQL sessions | Confirm the plugin matches the debugger architecture. Restart the debugger and run `doctor`. |
| A query requires a paused target | Pause the process, then retry. Check the session ID when multiple debuggers are open. |
| No output from the headless executable | Use redirected stdout, or run the terminal client interactively. |
| Static analyzer cannot connect | Check the loopback URL, listener port, and token. Use `static info` to confirm the analyzer sees the expected binary. |
