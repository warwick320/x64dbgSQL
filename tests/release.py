"""Validate the release archives and exercise the packaged headless client."""

from hashlib import file_digest
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from zipfile import ZipFile


BINARIES = {
    "x64dbgsql.exe", "x64dbgsql-headless.exe",
    "x64/plugins/x64dbgsql.dp64", "x32/plugins/x64dbgsql.dp32",
}
DOCUMENTATION = {"LICENSE", "README.md", "README.ko.md", "docs/usage.md",
                 "licenses/README.md", "licenses/nlohmann-json-MIT.txt"}
PRIVATE_NAMES = {"out", ".deps", ".git", "__pycache__", ".agents", ".codex", ".claude",
                 ".cursor", "agents.md", "agent.md", "claude.md", "gemini.md",
                 "copilot-instructions.md", "plan.ko.md"}


def archive_paths(archive):
    assert archive.testzip() is None, archive.filename
    paths = {entry.filename.replace(chr(92), "/") for entry in archive.infolist()
             if not entry.is_dir()}
    for name in paths:
        parts = name.lower().split("/")
        assert name != "benchmarks/tokens.py" and not PRIVATE_NAMES.intersection(parts), name
        assert not any(part == ".env" or part.startswith(".env.") for part in parts), name
        assert not name.endswith((".pyc", ".pyo", ".log")), name
    return paths


def validate(packages, dependencies, builds):
    expected = {"x64dbgsql-windows.zip", "x64dbgsql-source.zip", "x64dbgsql-setup.exe"}
    recorded = set()
    for line in (packages / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        checksum, name = line.split("  ", 1)
        assert name in expected and name not in recorded, name
        with (packages / name).open("rb") as stream:
            assert file_digest(stream, "sha256").hexdigest() == checksum, name
        recorded.add(name)
    assert recorded == expected, expected - recorded

    with TemporaryDirectory(prefix="x64dbgSQL release ") as directory:
        extracted = Path(directory)
        with ZipFile(packages / "x64dbgsql-windows.zip") as archive:
            candidates = archive_paths(archive)
            assert candidates == BINARIES | DOCUMENTATION, candidates ^ (BINARIES | DOCUMENTATION)
            for name in candidates:
                destination = extracted / name
                destination.parent.mkdir(parents=True, exist_ok=True)
                # Compress-Archive can use a Windows separator in entry names.
                entry = next(item for item in archive.namelist() if item.replace(chr(92), "/") == name)
                destination.write_bytes(archive.read(entry))
        with ZipFile(packages / "x64dbgsql-source.zip") as archive:
            source = archive_paths(archive)
            assert DOCUMENTATION | {".github/workflows/ci.yml", "CMakeLists.txt",
                "installer/x64dbgsql.iss", "tests/release.py"} <= source, source
            assert not any(Path(name).suffix.lower() in {".exe", ".dll", ".dp32", ".dp64"}
                           for name in source), source
        script = Path(__file__).with_name("windowless.py")
        for arch, platform, bits in (("x64", "x64", 64), ("x86", "x32", 32)):
            subprocess.run([
                sys.executable, "-B", script, extracted / "x64dbgsql-headless.exe",
                dependencies / platform / "headless.exe",
                extracted / platform / "plugins" / f"x64dbgsql.dp{bits}",
                builds / f"windows-{arch}" / "Release" / "x64dbgsql_fixture.exe",
            ], timeout=45, check=True)
            print(f"Packaged {arch} headless integration passed")


if __name__ == "__main__":
    validate(*[Path(path).resolve() for path in sys.argv[1:]])
