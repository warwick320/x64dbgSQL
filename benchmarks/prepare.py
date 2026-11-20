"""Stage two pristine Windows release clients without analyzing or running the sample."""
import argparse
import hashlib
import json
from pathlib import Path
import secrets
import shutil
import socket
import struct
import subprocess
import time
from urllib.request import ProxyHandler, Request, build_opener
from zipfile import ZipFile


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def unpack(archive, expected, target):
    actual = digest(archive)
    if actual != expected.lower():
        raise ValueError(f"Incorrect SHA-256 for {archive.name}")
    with ZipFile(archive) as zipped:
        zipped.extractall(target)
    return actual


def probe(host, plugin, settings, ready):
    setup = subprocess.STARTUPINFO()
    setup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    setup.wShowWindow = subprocess.SW_HIDE
    with subprocess.Popen(
        [host, "-userdir", settings, "-plugin", plugin], cwd=host.parent,
        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        startupinfo=setup, creationflags=subprocess.CREATE_NO_WINDOW,
    ) as debugger:
        try:
            deadline = time.monotonic() + 16
            while time.monotonic() < deadline and debugger.poll() is None:
                try:
                    if ready(debugger.pid):
                        return
                except OSError:
                    pass
                time.sleep(.15)
            raise RuntimeError(f"{plugin.name} failed readiness; debugger exit={debugger.poll()}")
        finally:
            if debugger.poll() is None:
                debugger.terminate()
                debugger.wait(timeout=5)


def stage(args):
    args.output.mkdir(parents=True)
    sql_root = args.output / "sql-release"
    mcp_root = args.output / "mcp-release"
    sql_digest = unpack(args.sql_zip, args.sql_sha256, sql_root)
    mcp_digest = unpack(args.mcp_zip, args.mcp_sha256, mcp_root)
    sample_digest = digest(args.sample)
    with args.sample.open("rb") as source:
        source.seek(0x3c)
        offset, = struct.unpack("<I", source.read(4))
        source.seek(offset)
        signature, machine = struct.unpack("<4sH", source.read(6))
    if signature != b"PE\0\0" or machine not in (0x8664, 0x14c):
        raise ValueError("Expected a Windows x86 or x64 PE")
    arch, extension = ("x64", "dp64") if machine == 0x8664 else ("x32", "dp32")
    manifest = {"sample_sha256": sample_digest, "architecture": arch,
                "sql_zip_sha256": sql_digest, "mcp_zip_sha256": mcp_digest,
                "client_clocks": "Windows perf_counter_ns", "lanes": {}}
    for name in ("sql", "mcp"):
        lane = args.output / name
        lane.mkdir()
        sample = lane / args.sample.name
        shutil.copyfile(args.sample, sample)
        assert digest(sample) == sample_digest
        install = lane / "debugger"
        install.mkdir()
        for entry in args.debugger.iterdir():
            if entry.is_file() and entry.suffix.lower() not in {".exe", ".ini"}:
                shutil.copyfile(entry, install / entry.name)
            elif entry.is_dir() and entry.name in {arch, "translations", "themes"}:
                shutil.copytree(entry, install / entry.name)
        host = install / arch / f"{arch}dbg.exe"
        if list((host.parent / "plugins").glob(f"*.{extension}")):
            raise ValueError("Use a debugger distribution without preinstalled plugins")
        settings = lane / "settings"
        settings.mkdir()
        if name == "sql":
            plugin = sql_root / arch / "plugins" / f"x64dbgsql.{extension}"
            cli = sql_root / "x64dbgsql.exe"

            def ready(pid):
                result = subprocess.run(
                    [cli, "sessions"], capture_output=True, encoding="utf8",
                    creationflags=subprocess.CREATE_NO_WINDOW, timeout=5, check=True)
                return any(item["pid"] == pid for item in json.loads(result.stdout)["sessions"])
        else:
            plugin = mcp_root / arch / "plugins" / f"x64dbg-MCP-Server.{extension}"
            with socket.socket() as reservation:
                reservation.bind(("127.0.0.1", 0))
                port = reservation.getsockname()[1]
            config = {"IpAddress": "127.0.0.1", "Port": port, "AutoStart": True,
                      "AuthToken": secrets.token_hex(24)}
            (host.parent / "mcp_config.json").write_text(json.dumps(config), encoding="ascii")
            cli = None
            opener = build_opener(ProxyHandler({}))

            def ready(_pid):
                def request(message):
                    request = Request(
                        f"http://127.0.0.1:{port}/", data=json.dumps(message).encode(),
                        headers={"Content-Type": "application/json",
                                 "Accept": "application/json, text/event-stream",
                                 "Authorization": "Bearer " + config["AuthToken"]})
                    with opener.open(request, timeout=3) as reply:
                        return json.load(reply)
                reply = request({"jsonrpc": "2.0", "method": "initialize", "id": 1,
                                 "params": {"protocolVersion": "2024-11-05",
                                            "capabilities": {}, "clientInfo": {
                                                "name": "benchmark-readiness", "version": "1"}}})
                assert "result" in reply
                return bool(request({"jsonrpc": "2.0", "method": "tools/list", "id": 2})
                            ["result"]["tools"])
        probe(host, plugin, settings, ready)
        manifest["lanes"][name] = {
            "sample": str(sample), "host": str(host), "plugin": str(plugin),
            "settings": str(settings), "cli": str(cli) if cli else None,
        }
        print(f"{name} release handshake passed with no debuggee", flush=True)
    (args.output / "preflight.json").write_text(json.dumps(manifest, indent=2), encoding="utf8")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    for option in ("sample", "sql-zip", "mcp-zip", "debugger", "output"):
        parser.add_argument(f"--{option}", required=True,
                            type=lambda path: Path(path).resolve())
    parser.add_argument("--sql-sha256", required=True)
    parser.add_argument("--mcp-sha256", required=True)
    stage(parser.parse_args())

