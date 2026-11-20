# x64dbgSQL

Query a live x64dbg session with SQL. Inspect registers, disassembly, loaded modules, and debugger events from a terminal, a script, or an MCP client.

[Download](https://github.com/warwick320/x64dbgSQL/releases) · [Usage guide](docs/usage.md) · [한국어](README.ko.md) · [MIT license](LICENSE)

## Install

Use an x64 Windows system and an extracted [x64dbg distribution](https://github.com/x64dbg/x64dbg/releases/tag/2026.05.27). The package includes plugins for both x64dbg and x32dbg and one x64 client shared by both.

1. Download **x64dbgsql-setup.exe** from [Releases](https://github.com/warwick320/x64dbgSQL/releases).
2. Close the debugger and any x64dbgSQL clients. Open the installer and select the writable x64dbg folder that contains `x64` and `x32`, typically named `release`.
3. Open the debugger and pause a program to start querying it.

For a portable install, extract **x64dbgsql-windows.zip** into the same folder. The ZIP contains both clients and the two plugins at `x64/plugins/x64dbgsql.dp64` and `x32/plugins/x64dbgsql.dp32`. Match the client and plugin versions when upgrading. Release downloads include `SHA256SUMS` for integrity checks.

Run the installer again in the same folder to upgrade. Remove an installer-managed copy through **Settings → Apps → Installed apps**. For a portable copy, remove the two x64dbgSQL executables and the corresponding plugin files manually. Move an older portable copy out of the debugger folder before switching to the installer.

## First query

Run these commands in the x64dbg folder while the target is paused.

```powershell
.\x64dbgsql.exe sessions
.\x64dbgsql.exe query -q 'SELECT * FROM stop_context'
.\x64dbgsql.exe query -q 'SELECT d.addr, d.text FROM session s JOIN disassembly(s.ip, 8) d'
```

Use `schema --offline` to list tables without a debugger. Pass `--session ID` when more than one session is available. Add `--json` for structured CLI output.

## MCP and headless use

Launch **`x64dbgsql-headless.exe`** for background tasks. It takes the same arguments as the terminal client and uses redirected standard input and output without opening a console. Configure a local stdio MCP client with the executable path and `["mcp", "--compact"]` as its arguments.

For an entirely windowless debugging session, use **x64dbg's `headless.exe`** for the debugger host as well. The [windowless launch example](docs/usage.md#headless-sessions) shows how to start both processes with working pipes. Any windows created by the target program depend on that program.

For unattended installation, pass `/VERYSILENT /SUPPRESSMSGBOXES /NORESTART /DIR="C:\Tools\x64dbg\release"` to the setup executable. See [installation and removal commands](docs/usage.md#unattended-installation).

## Use SQL across tools

- Join runtime addresses, registers, modules, and memory regions in a single query.
- Read disassembly and call stacks from a paused process.
- Compare checkpoints and inspect the event history of a session.
- Query existing IDASQL or GhidraSQL endpoints with projections, address ranges, and batched native reads.

See the [usage guide](docs/usage.md) for examples, connection settings, and troubleshooting.

## Build from source

Use Visual Studio 2022 Build Tools with the C++ workload, a Windows SDK, CMake 3.25+, and Python 3.11+ for integration tests. CMake verifies the pinned dependency downloads.

```powershell
foreach ($arch in 'x64', 'x86') {
    cmake --preset "windows-$arch"
    if ($LASTEXITCODE) { throw "Configure failed for $arch" }
    cmake --build --preset "windows-$arch"
    if ($LASTEXITCODE) { throw "Build failed for $arch" }
    ctest --preset "windows-$arch"
    if ($LASTEXITCODE) { throw "Tests failed for $arch" }
}
```

Run `./cmake/PackageWindows.ps1` to produce the portable and source ZIPs. Pass `-InnoCompiler <path-to-ISCC.exe>` to produce the installer as well. Packages and checksums go to `out/packages`. See the [build and release notes](docs/usage.md#building-release-packages) for the full command.

x64dbgSQL is distributed under the [MIT License](LICENSE). [Third-party notices](licenses/README.md) are included with the distribution.
