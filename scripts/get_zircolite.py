"""Download the pinned Zircolite standalone binary into .tools/ and verify its SHA-256."""

from __future__ import annotations

import hashlib
import sys
import urllib.request
import zipfile
from pathlib import Path

from common import ROOT

VERSION = "4.1.0"
BASE_URL = f"https://github.com/wagga40/Zircolite/releases/download/v{VERSION}"
ASSETS = {
    "linux": (
        f"Zircolite-{VERSION}-linux-x64.zip",
        "cbaf33c74c3ac3c2bb299dfba16fdba6557d9e2d8c09479e13ed12f11ec6f9f1",
    ),
    "win32": (
        f"Zircolite-{VERSION}-windows-x64.zip",
        "d2256f2f227ca395e27d7ccf4d5a569a88d8aa01143e01664d3e65fef4021f57",
    ),
}


def verify_sha256(path: Path, expected: str) -> None:
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise ValueError(f"SHA-256 mismatch for {path.name}: expected {expected}, got {actual}")


def exe_path(tools_dir: Path, platform: str) -> Path:
    folder = tools_dir / ASSETS[platform][0].removesuffix(".zip")
    return folder / ("Zircolite.exe" if platform == "win32" else "Zircolite")


def ensure(tools_dir: Path) -> Path:
    platform = "win32" if sys.platform == "win32" else "linux"
    exe = exe_path(tools_dir, platform)
    if exe.exists():
        return exe
    name, digest = ASSETS[platform]
    tools_dir.mkdir(parents=True, exist_ok=True)
    archive = tools_dir / name
    urllib.request.urlretrieve(f"{BASE_URL}/{name}", archive)
    verify_sha256(archive, digest)
    with zipfile.ZipFile(archive) as zf:
        zf.extractall(tools_dir)
    archive.unlink()
    if platform == "linux":
        exe.chmod(0o755)  # zipfile does not keep the executable bit
    return exe


def main() -> int:
    print(ensure(ROOT / ".tools"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
