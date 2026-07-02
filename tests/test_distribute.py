from app.matching.distribute import _cvss_attack_vector


def test_cvss_attack_vector_network():
    assert _cvss_attack_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == "NETWORK"


def test_cvss_attack_vector_local():
    assert _cvss_attack_vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == "LOCAL"


def test_cvss_attack_vector_missing():
    assert _cvss_attack_vector(None) is None
    assert _cvss_attack_vector("") is None


def test_cvss_attack_vector_malformed():
    assert _cvss_attack_vector("not-a-cvss-vector") is None
