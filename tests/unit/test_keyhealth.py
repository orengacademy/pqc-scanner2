from math import prod

from pqcscan.core.keyhealth import analyze_rsa_modulus, is_roca_vulnerable

_FINGERPRINT_PRIMES = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167,
)


def _roca_form_modulus() -> int:
    """A modulus of the exact Infineon form n ≡ 65537^k (mod M), where M is
    the primorial of the fingerprint primes — guaranteed to fingerprint."""
    m = prod(_FINGERPRINT_PRIMES)
    return pow(65537, 12345, m) + m


def test_roca_form_modulus_detected():
    assert is_roca_vulnerable(_roca_form_modulus())


def test_random_modulus_is_not_roca():
    n = 0xC0FFEE1234567890ABCDEF0987654321FEDCBA0011223344556677889900AABB
    assert not is_roca_vulnerable(n)


def test_small_modulus_flagged():
    h = analyze_rsa_modulus(0xDEADBEEF, bit_length=512)
    assert not h.ok
    assert any("512 bits" in i for i in h.issues)


def test_roca_modulus_flagged_by_analyze():
    h = analyze_rsa_modulus(_roca_form_modulus(), bit_length=2048)
    assert not h.ok
    assert any("ROCA" in i for i in h.issues)


def test_healthy_modulus_ok():
    n = 0xC0FFEE1234567890ABCDEF0987654321FEDCBA0011223344556677889900AABB
    h = analyze_rsa_modulus(n, bit_length=2048)
    assert h.ok
