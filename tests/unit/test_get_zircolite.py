import hashlib
from pathlib import Path

import pytest
from get_zircolite import ASSETS, exe_path, verify_sha256


def test_assets_pinned_to_4_1_0():
    assert ASSETS["linux"] == (
        "Zircolite-4.1.0-linux-x64.zip",
        "cbaf33c74c3ac3c2bb299dfba16fdba6557d9e2d8c09479e13ed12f11ec6f9f1",
    )
    assert ASSETS["win32"] == (
        "Zircolite-4.1.0-windows-x64.zip",
        "d2256f2f227ca395e27d7ccf4d5a569a88d8aa01143e01664d3e65fef4021f57",
    )


def test_verify_sha256(tmp_path: Path):
    p = tmp_path / "f.zip"
    p.write_bytes(b"abc")
    verify_sha256(p, hashlib.sha256(b"abc").hexdigest())
    with pytest.raises(ValueError, match="SHA-256 mismatch"):
        verify_sha256(p, "0" * 64)


def test_exe_path(tmp_path: Path):
    assert exe_path(tmp_path, "win32") == tmp_path / "Zircolite-4.1.0-windows-x64" / "Zircolite.exe"
    assert exe_path(tmp_path, "linux") == tmp_path / "Zircolite-4.1.0-linux-x64" / "Zircolite"
