"""User-level Linux and macOS service management."""

from __future__ import annotations

import os
import plistlib
import shutil
import subprocess
import sys
from pathlib import Path

from tether_agent.paths import ProfilePaths
from tether_agent.secure_files import atomic_write


def _executable() -> Path:
    discovered = shutil.which("tb-agent")
    if discovered:
        return Path(discovered).resolve()
    return Path(sys.argv[0]).resolve()


def _systemd_name(profile: str) -> str:
    # The unit identity is persistent state and must survive the executable rename.
    return f"tether-agent-{profile}.service"


def _launchd_label(profile: str) -> str:
    return f"net.tetherbrain.agent.{profile}"


def _systemd_path(paths: ProfilePaths) -> Path:
    return Path.home() / ".config" / "systemd" / "user" / _systemd_name(paths.profile)


def _launchd_path(paths: ProfilePaths) -> Path:
    return (
        Path.home()
        / "Library"
        / "LaunchAgents"
        / f"{_launchd_label(paths.profile)}.plist"
    )


def _systemd_definition(paths: ProfilePaths, executable: Path) -> bytes:
    escaped = str(executable).replace("\\", "\\\\").replace('"', '\\"')
    profile = paths.profile.replace("\\", "\\\\").replace('"', '\\"')
    return (
        "[Unit]\n"
        f"Description=Tether Agent ({profile})\n"
        "After=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f'ExecStart="{escaped}" --profile "{profile}" run\n'
        "Restart=on-failure\n"
        "RestartSec=5\n\n"
        "[Install]\n"
        "WantedBy=default.target\n"
    ).encode()


def _launchd_definition(paths: ProfilePaths, executable: Path) -> bytes:
    return plistlib.dumps(
        {
            "Label": _launchd_label(paths.profile),
            "ProgramArguments": [
                str(executable),
                "--profile",
                paths.profile,
                "run",
            ],
            "KeepAlive": {"SuccessfulExit": False},
            "RunAtLoad": False,
        },
        fmt=plistlib.FMT_XML,
        sort_keys=True,
    )


class ServiceManager:
    def __init__(self, paths: ProfilePaths, *, platform: str | None = None) -> None:
        self.paths = paths
        self.platform = sys.platform if platform is None else platform

    def _supported(self) -> None:
        if self.platform not in {"linux", "darwin"}:
            raise RuntimeError(
                "Background services are supported only on Linux and macOS. "
                "Run 'tb-agent run' in the foreground on Windows."
            )

    def install(self) -> None:
        self._supported()
        executable = _executable()
        if self.platform == "linux":
            atomic_write(
                _systemd_path(self.paths),
                _systemd_definition(self.paths, executable),
                private_parent=False,
            )
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
            subprocess.run(
                ["systemctl", "--user", "enable", _systemd_name(self.paths.profile)],
                check=True,
            )
            return
        atomic_write(
            _launchd_path(self.paths),
            _launchd_definition(self.paths, executable),
            private_parent=False,
        )

    def uninstall(self) -> None:
        self._supported()
        self.stop(check=False)
        if self.platform == "linux":
            subprocess.run(
                ["systemctl", "--user", "disable", _systemd_name(self.paths.profile)],
                check=False,
            )
            _systemd_path(self.paths).unlink(missing_ok=True)
            subprocess.run(["systemctl", "--user", "daemon-reload"], check=True)
            return
        _launchd_path(self.paths).unlink(missing_ok=True)

    def start(self) -> None:
        self._supported()
        if self.platform == "linux":
            subprocess.run(
                ["systemctl", "--user", "start", _systemd_name(self.paths.profile)],
                check=True,
            )
            return
        subprocess.run(
            [
                "launchctl",
                "bootstrap",
                f"gui/{os.getuid()}",
                str(_launchd_path(self.paths)),
            ],
            check=True,
        )

    def stop(self, *, check: bool = True) -> None:
        self._supported()
        if self.platform == "linux":
            subprocess.run(
                ["systemctl", "--user", "stop", _systemd_name(self.paths.profile)],
                check=check,
            )
            return
        subprocess.run(
            [
                "launchctl",
                "bootout",
                f"gui/{os.getuid()}/{_launchd_label(self.paths.profile)}",
            ],
            check=check,
        )

    def restart(self) -> None:
        self._supported()
        if self.platform == "linux":
            subprocess.run(
                ["systemctl", "--user", "restart", _systemd_name(self.paths.profile)],
                check=True,
            )
            return
        self.stop(check=False)
        self.start()

    def status(self) -> int:
        self._supported()
        if self.platform == "linux":
            definition = _systemd_path(self.paths)
            if definition.exists() and 'tether-agent"' in definition.read_text(
                encoding="utf-8", errors="replace"
            ):
                print(
                    "Warning: this service invokes the removed tether-agent executable. "
                    "Run 'tb-agent service install' to update it before starting the service."
                )
        command = (
            ["systemctl", "--user", "status", _systemd_name(self.paths.profile)]
            if self.platform == "linux"
            else [
                "launchctl",
                "print",
                f"gui/{os.getuid()}/{_launchd_label(self.paths.profile)}",
            ]
        )
        return subprocess.run(command, check=False).returncode

    def logs(self) -> int:
        self._supported()
        if self.platform == "linux":
            return subprocess.run(
                [
                    "journalctl",
                    "--user",
                    "--unit",
                    _systemd_name(self.paths.profile),
                    "--lines",
                    "200",
                    "--no-pager",
                ],
                check=False,
            ).returncode
        if not self.paths.log_file.exists():
            print("No daemon log exists for this profile yet.")
            return 0
        lines = self.paths.log_file.read_text(
            encoding="utf-8",
            errors="replace",
        ).splitlines()
        print("\n".join(lines[-200:]))
        return 0
