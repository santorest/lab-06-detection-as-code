"""Convert every rule with sigma-cli and compare against the golden files in tests/expected/<backend>/."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

from common import BACKENDS, ROOT, Rule, load_rules, load_support, load_targets


class ConvertError(RuntimeError):
    pass


def normalize(text: str) -> str:
    lines = text.lstrip("﻿").replace("\r\n", "\n").strip().split("\n")
    return "\n".join(line.rstrip() for line in lines) + "\n"


def sigma_exe() -> str:
    exe = Path(sys.executable).with_name("sigma.exe" if os.name == "nt" else "sigma")
    return str(exe) if exe.exists() else "sigma"


def _error_line(output: str) -> str:
    """sigma-cli's `Error: ...` line (without the prefixes), else the last non-empty line."""
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    for line in lines:
        if line.startswith("Error:"):
            return line.removeprefix("Error:").strip().removeprefix("Error while converting:").strip()
    return lines[-1] if lines else ""


def convert(rule: Rule, backend: str, args: list[str], root: Path) -> str:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "out.txt"
        cmd = [sigma_exe(), "convert", "-t", backend, *args, "-o", str(out), str(rule.path)]
        proc = subprocess.run(
            cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", cwd=root, check=False
        )
        if proc.returncode != 0 or not out.exists():
            raise ConvertError(_error_line(proc.stderr + proc.stdout) or f"exit {proc.returncode}")
        return normalize(out.read_text(encoding="utf-8"))


Runner = Callable[[Rule, str, list[str], Path], str]


def check(root: Path, backends: list[str], update: bool, run: Runner = convert) -> list[str]:
    errors: list[str] = []
    rules = load_rules(root / "rules")
    slugs = {r.slug for r in rules}
    support = load_support(root / "support.yaml")
    targets = load_targets(root / "targets.yaml")
    for backend in backends:
        golden_dir = root / "tests" / "expected" / backend
        for golden in sorted(golden_dir.glob("*.txt")) if golden_dir.is_dir() else []:
            if golden.stem not in slugs:
                if update:
                    golden.unlink()
                else:
                    errors.append(f"{backend}/{golden.name}: orphan golden (no rule)")
        for rule in rules:
            name = f"{rule.slug} [{backend}]"
            golden = golden_dir / f"{rule.slug}.txt"
            args = (targets.get(rule.platform) or {}).get("convert", {}).get(backend)
            excl = support.get((rule.slug, backend))
            if excl:
                if golden.exists():
                    errors.append(f"{name}: golden file exists for excluded pair")
                if excl.kind == "unsupported":
                    try:
                        run(rule, backend, args or [], root)
                        errors.append(f"{name}: exclusion is stale (conversion now works): remove it")
                    except ConvertError:
                        pass
                continue
            if args is None:
                errors.append(f"{name}: no targets.yaml args for {rule.platform}.convert.{backend}")
                continue
            try:
                text = run(rule, backend, args, root)
            except ConvertError as exc:
                errors.append(f"{name}: conversion failed: {exc}")
                continue
            if update:
                golden.parent.mkdir(parents=True, exist_ok=True)
                golden.write_text(text, encoding="utf-8", newline="\n")
            elif not golden.exists():
                errors.append(f"{name}: missing golden {backend}/{golden.name} (run convert.py --update)")
            elif normalize(golden.read_text(encoding="utf-8")) != text:
                errors.append(f"{name}: golden mismatch (review the diff, then run convert.py --update)")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--update", action="store_true", help="rewrite golden files")
    parser.add_argument("--backend", action="append", choices=BACKENDS, help="default: all")
    ns = parser.parse_args()
    errors = check(ROOT, ns.backend or list(BACKENDS), ns.update)
    for e in errors:
        print(e)
    print(f"convert: {len(errors)} error(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
