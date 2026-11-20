"""Exercise silent install, upgrade, and uninstall in disposable directories."""

from pathlib import Path
from shutil import copy2
import subprocess
import sys
from tempfile import TemporaryDirectory
from time import monotonic, sleep
import winreg


APP_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\x64dbgSQL.warwick320_is1"


def installed_location():
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, APP_KEY) as key:
            return winreg.QueryValueEx(key, "InstallLocation")[0]
    except FileNotFoundError:
        return None


def run(executable, *args):
    return subprocess.run([executable, "/VERYSILENT", "/SUPPRESSMSGBOXES",
                           "/NORESTART", *args], stdin=subprocess.DEVNULL,
                          capture_output=True, timeout=45,
                          creationflags=subprocess.CREATE_NO_WINDOW).returncode


def uninstall(target):
    uninstaller, = (target / ".x64dbgsql").glob("unins*.exe")
    assert run(uninstaller) == 0, target
    deadline = monotonic() + 10
    while installed_location() or uninstaller.exists():
        assert monotonic() < deadline, "Uninstaller did not finish cleanup"
        sleep(0.05)


def check_install(setup, release, target, platforms):
    host_files = {"settings.ini": b"keep user settings",
                  **{f"{platform}/plugins/keep.dat": b"keep another plugin"
                     for platform in platforms}}
    for platform in platforms:
        host = f"{platform}/{platform}dbg.exe"
        (target / platform).mkdir(parents=True)
        copy2(release / host, target / host)
        host_files[host] = (target / host).read_bytes()
    for name, content in host_files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    files = ["x64dbgsql.exe", "x64dbgsql-headless.exe", ".x64dbgsql/LICENSE"]
    files += [f"{platform}/plugins/x64dbgsql.dp{platform[1:]}" for platform in platforms]
    managed = target / files[-1]
    managed.write_bytes(b"unmanaged plugin")
    assert run(setup, f"/DIR={target}") != 0, "Installer accepted an unmanaged plugin"
    assert managed.read_bytes() == b"unmanaged plugin"
    managed.unlink()

    try:
        for _ in range(2):
            assert run(setup, f"/DIR={target}") == 0, target
            for name in files:
                assert (target / name).is_file(), name
            for platform in {"x32", "x64"}.difference(platforms):
                assert not (target / platform).exists(), platform
            result = subprocess.run([target / "x64dbgsql-headless.exe", "schema", "--offline"],
                                    capture_output=True, check=True, timeout=10)
            assert b'"ok":true' in result.stdout, result.stdout
    finally:
        if installed_location():
            uninstall(target)

    for name in files:
        assert not (target / name).exists(), name
    for name, content in host_files.items():
        assert (target / name).read_bytes() == content, name


if __name__ == "__main__":
    setup, release = map(lambda value: Path(value).resolve(), sys.argv[1:])
    assert setup.is_file(), f"Installer is missing: {setup}"
    assert not installed_location(), "Use a user profile without an existing x64dbgSQL installation"
    with TemporaryDirectory(prefix="x64dbgSQL installer ") as temp:
        root = Path(temp)
        assert run(setup, f"/DIR={root}") != 0, "Installer accepted an empty folder"
        assert not installed_location()
        check_install(setup, release, root / "both", ("x64", "x32"))
        check_install(setup, release, root / "32 only", ("x32",))
    print("Silent installation, upgrade, collision protection, and removal passed")
