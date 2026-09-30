from sigma.data import mitre_attack
from sigma_check import ATTACK_URL, configure


def test_attack_data_pinned_to_versioned_file_at_a_commit():
    assert ATTACK_URL == (
        "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
        "6cda5ad8462c79e14fbb872f4e09059b18e0cfc4/enterprise-attack/enterprise-attack-19.2.json"
    )


def test_configure_points_pysigma_at_the_pinned_file():
    configure()
    assert mitre_attack._custom_url == ATTACK_URL
