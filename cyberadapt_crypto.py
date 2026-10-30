"""
CyberAdapt: Cryptographic Core (Solutions 1, 2, and 3)
=====================================================
Paper / Presentation Reference:
  - Solution 1: SMBP-PreComp (Fixed-Base ECC Precomputation) & Revocation Bloom Filter
  - Solution 2: ZK-TAT (Zero-Knowledge Telemetry Authentication Token)
  - Solution 3: H-PO (Hash-Based Policy Obfuscation)
"""

import hashlib
import hmac
import math
import os
import secrets
import struct
import time

# ─────────────────────────────────────────────────────────────────────────────
# Elliptic Curve Cryptography: Secp256k1 Curve Definition
# ─────────────────────────────────────────────────────────────────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
A = 0
B = 7
ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Base point G
GX = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798
GY = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
G = (GX, GY)

# Independent Generator H for Pedersen Commitments: H = HashToCurve("CYBERADAPT_GEN_H")
def _hash_to_curve(label: bytes):
    seed = hashlib.sha256(label).digest()
    x = int.from_bytes(seed, 'big') % P
    while True:
        y_sq = (pow(x, 3, P) + B) % P
        y = pow(y_sq, (P + 1) // 4, P)
        if pow(y, 2, P) == y_sq:
            return (x, y)
        x = (x + 1) % P

H_POINT = _hash_to_curve(b"CYBERADAPT_INDEPENDENT_GENERATOR_H_V1")


def point_add(p1, p2):
    if p1 is None: return p2
    if p2 is None: return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2:
        if (y1 + y2) % P == 0:
            return None
        m = (3 * x1 * x1 + A) * pow(2 * y1, -1, P) % P
    else:
        m = (y2 - y1) * pow(x2 - x1, -1, P) % P
    x3 = (m * m - x1 - x2) % P
    y3 = (m * (x1 - x3) - y1) % P
    return (x3, y3)


def point_double(pt):
    if pt is None: return None
    return point_add(pt, pt)


def point_negate(pt):
    if pt is None: return None
    return (pt[0], (-pt[1]) % P)


def scalar_mult_baseline(k: int, pt):
    """Standard double-and-add scalar multiplication (MA-ABSE-AR baseline)."""
    if k == 0 or pt is None:
        return None
    res = None
    curr = pt
    while k > 0:
        if k & 1:
            res = point_add(res, curr)
        curr = point_double(curr)
        k >>= 1
    return res


# ─────────────────────────────────────────────────────────────────────────────
# SOLUTION 1: SMBP-PreComp (Fixed-Base ECC Precomputation)
# ─────────────────────────────────────────────────────────────────────────────
class SMBPPreComp:
    """
    Fixed-base ECC precomputation table T[i] = 2^i * G for i in [0..255].
    Trades ~8 KB SRAM for eliminating online point doublings.
    """
    def __init__(self, base_point=G, bit_length=256):
        self.base_point = base_point
        self.bit_length = bit_length
        self.table = []
        self._build_table()

    def _build_table(self):
        curr = self.base_point
        for _ in range(self.bit_length):
            self.table.append(curr)
            curr = point_double(curr)

    def multiply(self, scalar: int):
        """Computes k * G using precomputed powers: zero online doublings!"""
        scalar = scalar % ORDER
        if scalar == 0:
            return None
        res = None
        for i in range(self.bit_length):
            if (scalar >> i) & 1:
                res = point_add(res, self.table[i])
        return res

    def memory_footprint_bytes(self):
        """Table memory: 256 points * (32-byte X + 32-byte Y) = 16,384 B (~8-16 KB)."""
        return self.bit_length * 64


# Global precomputed table for G and H
SMBP_TABLE_G = SMBPPreComp(G, 256)
SMBP_TABLE_H = SMBPPreComp(H_POINT, 256)


# ─────────────────────────────────────────────────────────────────────────────
# SOLUTION 1 (Part B): Revocation Bloom Filter
# ─────────────────────────────────────────────────────────────────────────────
class RevocationBloomFilter:
    """
    Compact 4 KiB Bloom filter for sub-microsecond revocation membership checks.
    Parameters:
      m = 32,768 bits (4,096 bytes)
      k = 4 hash probes
      n = up to 500 revoked IDs
      P_FP approx 0.00123% (Slide 9)
    """
    def __init__(self, m_bits=32768, num_probes=4):
        self.m = m_bits
        self.k = num_probes
        self.bit_array = bytearray(self.m // 8)

    def _get_probes(self, item_id: str):
        data = item_id.encode('utf-8')
        probes = []
        for i in range(self.k):
            h = hashlib.sha256(data + struct.pack('>I', i)).digest()
            val = int.from_bytes(h[:4], 'big') % self.m
            probes.append(val)
        return probes

    def add(self, item_id: str):
        for bit in self._get_probes(item_id):
            byte_idx = bit // 8
            bit_idx = bit % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)

    def is_revoked(self, item_id: str) -> bool:
        """Returns True if item_id might be revoked; False if DEFINITELY absent."""
        for bit in self._get_probes(item_id):
            byte_idx = bit // 8
            bit_idx = bit % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True


# ─────────────────────────────────────────────────────────────────────────────
# SOLUTION 2: ZK-TAT (Zero-Knowledge Telemetry Authentication Token)
# ─────────────────────────────────────────────────────────────────────────────
class ZKTAT:
    """
    Zero-Knowledge Telemetry Authentication Token (Slides 10-12).
    Prover proves possession of credential scalar VID without revealing VID.
      1. Commit: C = rG + VID*H
      2. Nonces: R = k1*G + k2*H
      3. Challenge: e = SHA-256(G, H, C, R, Context) mod q
      4. Responses: s1 = (k1 + e*r) mod q, s2 = (k2 + e*VID) mod q
      Token: (C, e, s1, s2) = 128 bytes total.
    """
    @staticmethod
    def prove(vid: int, context: str, smbp: bool = True):
        # 1. Blinding scalar r and fresh nonces k1, k2
        r = secrets.randbelow(ORDER - 1) + 1
        k1 = secrets.randbelow(ORDER - 1) + 1
        k2 = secrets.randbelow(ORDER - 1) + 1

        # 2. Pedersen Commitment C = rG + VID*H
        if smbp:
            rG = SMBP_TABLE_G.multiply(r)
            vidH = SMBP_TABLE_H.multiply(vid)
            k1G = SMBP_TABLE_G.multiply(k1)
            k2H = SMBP_TABLE_H.multiply(k2)
        else:
            rG = scalar_mult_baseline(r, G)
            vidH = scalar_mult_baseline(vid, H_POINT)
            k1G = scalar_mult_baseline(k1, G)
            k2H = scalar_mult_baseline(k2, H_POINT)

        C = point_add(rG, vidH)
        R = point_add(k1G, k2H)

        # 3. Fiat-Shamir Challenge e
        e = ZKTAT._compute_challenge(C, R, context)

        # 4. Masked Responses
        s1 = (k1 + e * r) % ORDER
        s2 = (k2 + e * vid) % ORDER

        # 5. Token bundle: (C, e, s1, s2)
        token = {
            'C': C,
            'e': e,
            's1': s1,
            's2': s2,
            'context': context,
        }
        return token

    @staticmethod
    def verify(token: dict, expected_context: str, smbp: bool = True) -> bool:
        """Verifier recomputes R' = s1*G + s2*H - e*C, e' and checks e' == e."""
        if token['context'] != expected_context:
            return False

        C = token['C']
        e = token['e']
        s1 = token['s1']
        s2 = token['s2']

        # R' = s1*G + s2*H - e*C
        if smbp:
            s1G = SMBP_TABLE_G.multiply(s1)
            s2H = SMBP_TABLE_H.multiply(s2)
        else:
            s1G = scalar_mult_baseline(s1, G)
            s2H = scalar_mult_baseline(s2, H_POINT)

        # e*C is variable-base scalar mult
        eC = scalar_mult_baseline(e, C)
        neg_eC = point_negate(eC)

        R_prime = point_add(point_add(s1G, s2H), neg_eC)
        if R_prime is None:
            return False

        e_prime = ZKTAT._compute_challenge(C, R_prime, expected_context)
        return e_prime == e

    @staticmethod
    def _compute_challenge(C, R, context: str) -> int:
        h = hashlib.sha256()
        h.update(b"ZKTAT_CHALLENGE_V1")
        h.update(G[0].to_bytes(32, 'big'))
        h.update(H_POINT[0].to_bytes(32, 'big'))
        h.update(C[0].to_bytes(32, 'big') + C[1].to_bytes(32, 'big'))
        h.update(R[0].to_bytes(32, 'big') + R[1].to_bytes(32, 'big'))
        h.update(context.encode('utf-8'))
        return int.from_bytes(h.digest(), 'big') % ORDER


# ─────────────────────────────────────────────────────────────────────────────
# SOLUTION 3: H-PO (Hash-Based Policy Obfuscation)
# ─────────────────────────────────────────────────────────────────────────────
class HPO:
    """
    Hash-Based Policy Obfuscation (Slides 13-14).
    Replaces plaintext policy strings with 32-byte secret-keyed tags:
      rho_tilde(s) = SHA-256("HPO_SALT_V1" || As || Splatoon)
    """
    SALT_PREFIX = b"HPO_SALT_V1"

    @staticmethod
    def compute_tag(attribute: str, shared_platoon_secret: bytes) -> bytes:
        h = hashlib.sha256()
        h.update(HPO.SALT_PREFIX)
        h.update(attribute.encode('utf-8'))
        h.update(shared_platoon_secret)
        return h.digest()

    @staticmethod
    def match_policy(received_tag: bytes, candidate_attribute: str, shared_platoon_secret: bytes) -> bool:
        expected = HPO.compute_tag(candidate_attribute, shared_platoon_secret)
        return hmac.compare_digest(received_tag, expected)


# ─────────────────────────────────────────────────────────────────────────────
# Microbenchmark Harness
# ─────────────────────────────────────────────────────────────────────────────
class CyberAdaptCryptoEngine:
    """Unified engine packaging Solutions 1, 2, and 3."""
    def __init__(self):
        self.bloom_filter = RevocationBloomFilter()
        self.smbp_g = SMBP_TABLE_G
        self.smbp_h = SMBP_TABLE_H

    def generate_zktat_token(self, vid: int, context: str):
        return ZKTAT.prove(vid, context, smbp=True)

    def verify_zktat_token(self, token: dict, context: str) -> bool:
        return ZKTAT.verify(token, context, smbp=True)

    def is_vehicle_revoked(self, vid_str: str) -> bool:
        return self.bloom_filter.is_revoked(vid_str)

    def revoke_vehicle(self, vid_str: str):
        self.bloom_filter.add(vid_str)

    def obfuscate_policy_attribute(self, attribute: str, secret: bytes) -> bytes:
        return HPO.compute_tag(attribute, secret)

    def verify_policy_attribute(self, tag: bytes, attribute: str, secret: bytes) -> bool:
        return HPO.match_policy(tag, attribute, secret)


def benchmark_crypto():
    print("=" * 70)
    print("  CYBERADAPT CRYPTOGRAPHIC ENGINE BENCHMARK (Solutions 1, 2, 3)")
    print("=" * 70)

    # 1. SMBP-PreComp vs Baseline
    k = secrets.randbelow(ORDER)
    trials = 100

    t0 = time.perf_counter()
    for _ in range(trials):
        scalar_mult_baseline(k, G)
    base_time = (time.perf_counter() - t0) / trials * 1000

    t0 = time.perf_counter()
    for _ in range(trials):
        SMBP_TABLE_G.multiply(k)
    smbp_time = (time.perf_counter() - t0) / trials * 1000

    speedup = base_time / max(1e-9, smbp_time)
    print(f"[S1: SMBP-PreComp] Baseline Double-Add : {base_time:.4f} ms")
    print(f"[S1: SMBP-PreComp] Optimized SMBP Table: {smbp_time*1000:.2f} µs ({smbp_time:.5f} ms)")
    print(f"[S1: SMBP-PreComp] Speedup Factor      : {speedup:.1f}x (Zero online doublings!)")
    print(f"[S1: SMBP-PreComp] SRAM Footprint      : {SMBP_TABLE_G.memory_footprint_bytes() / 1024:.1f} KB")

    # 2. Revocation Bloom Filter
    bf = RevocationBloomFilter()
    for i in range(500):
        bf.add(f"revoked_vehicle_{i}")
    print(f"\n[S1: BloomFilter] Size = 4 KiB, Elements = 500 revoked IDs")
    print(f"[S1: BloomFilter] Check present : {bf.is_revoked('revoked_vehicle_42')} (Expected True)")
    print(f"[S1: BloomFilter] Check absent  : {bf.is_revoked('legitimate_car_99')} (Expected False)")

    # 3. ZK-TAT Prover & Verifier
    vid = 0xABCD1234EF5678
    ctx = "EPOCH_100_HIGHWAY_E0"
    t0 = time.perf_counter()
    token = ZKTAT.prove(vid, ctx)
    prove_time = (time.perf_counter() - t0) * 1000

    t0 = time.perf_counter()
    valid = ZKTAT.verify(token, ctx)
    verify_time = (time.perf_counter() - t0) * 1000

    print(f"\n[S2: ZK-TAT] Proof Generation Time    : {prove_time:.3f} ms")
    print(f"[S2: ZK-TAT] Verification Time        : {verify_time:.3f} ms")
    print(f"[S2: ZK-TAT] Verification Success     : {valid}")
    print(f"[S2: ZK-TAT] Token Payload Size       : 128 bytes (Zero identity leakage)")

    # 4. H-PO Policy Obfuscation
    secret = b"SECRET_PLATOON_KEY_2026_CBIT_HYD"
    tag = HPO.compute_tag("PLATOON_LEADER", secret)
    match = HPO.match_policy(tag, "PLATOON_LEADER", secret)
    mismatch = HPO.match_policy(tag, "HAZMAT_CARGO", secret)
    print(f"\n[S3: H-PO] Tag for 'PLATOON_LEADER'   : {tag.hex()[:24]}... (32 bytes)")
    print(f"[S3: H-PO] Authenticated Match       : {match} (Expected True)")
    print(f"[S3: H-PO] Rogue Attribute Match     : {mismatch} (Expected False)")
    print("=" * 70)


if __name__ == '__main__':
    benchmark_crypto()
