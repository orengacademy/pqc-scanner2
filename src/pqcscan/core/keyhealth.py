"""Public-key health checks that use only public key material.

These flag RSA moduli that are weak for reasons *independent* of the quantum
threat — a scanner that reports "RSA-2048, migrate by 2030" while silently
sitting on a ROCA-factorable key would be missing a today-exploitable break.
We never touch private material; every check takes a public modulus integer.

- ROCA (CVE-2017-15361): Infineon RSALib generated primes of a special form,
  making moduli practically factorable. Detected by the discrete-log
  fingerprint from Nemec et al., "The Return of Coppersmith's Attack" (2017).
- Small modulus: < 1024-bit RSA is factorable now, not just under Shor.
"""
from __future__ import annotations

from dataclasses import dataclass
from math import gcd

# The 38 small primes whose primorial ROCA keys are structured around, and
# the per-prime residue sets Infineon's generator can produce. Precomputed
# from the published algorithm so the check is a fast membership test.
_ROCA_PRIMES: tuple[int, ...] = (
    3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67,
    71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139,
    149, 151, 157, 163, 167,
)


def _multiplicative_order(a: int, m: int) -> int:
    """Order of `a` in the multiplicative group mod `m`."""
    if gcd(a, m) != 1:
        return 0
    order = 1
    val = a % m
    while val != 1:
        val = (val * a) % m
        order += 1
        if order > m:
            return 0
    return order


def is_roca_vulnerable(modulus: int) -> bool:
    """True if `modulus` bears the Infineon RSALib (ROCA) fingerprint.

    For each small prime p, a genuine ROCA modulus is congruent to a power
    of 65537 modulo p. A random modulus fails this for some p almost surely,
    so the joint test has a negligible false-positive rate.
    """
    if modulus < 3:
        return False
    generator = 65537
    for prime in _ROCA_PRIMES:
        order = _multiplicative_order(generator, prime)
        if order == 0:
            continue
        residue = modulus % prime
        # Collect the residues 65537^k mod p can take; the modulus must land
        # in that set for the fingerprint to hold.
        powers = set()
        val = 1
        for _ in range(order):
            powers.add(val)
            val = (val * generator) % prime
        if residue not in powers:
            return False
    return True


@dataclass(slots=True)
class KeyHealth:
    ok: bool
    issues: tuple[str, ...] = ()


def analyze_rsa_modulus(modulus: int, bit_length: int | None = None) -> KeyHealth:
    """Classical-health verdict for an RSA public modulus."""
    issues: list[str] = []
    bits = bit_length if bit_length is not None else modulus.bit_length()
    if bits < 1024:
        issues.append(f"RSA modulus is only {bits} bits — factorable with current compute")
    if is_roca_vulnerable(modulus):
        issues.append("ROCA (CVE-2017-15361): Infineon RSALib key, practically factorable")
    return KeyHealth(ok=not issues, issues=tuple(issues))
