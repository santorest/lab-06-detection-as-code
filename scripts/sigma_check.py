"""`sigma check` against a pinned ATT&CK release.

sigma-cli validates ATT&CK tags against data pySigma downloads from the attack-stix-data *master* branch, so a new
ATT&CK release can break CI overnight. This wrapper points pySigma at a versioned file at a fixed commit.
Usage: python scripts/sigma_check.py [sigma check options] rules/
"""

from __future__ import annotations

import sys

from sigma.data import mitre_attack

ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json"
)


def configure() -> None:
    mitre_attack.set_url(ATTACK_URL)


def main(argv: list[str]) -> None:
    configure()
    from sigma.cli.check import check

    check.main(args=argv, prog_name="sigma check")


if __name__ == "__main__":
    main(sys.argv[1:])
