"""ML-DSA parameter sets, copied from FIPS 204 Table 1 and Table 2.

The cryptographic library does the actual math; these values are used to
display the parameters and to check that key/signature sizes match the
standard exactly (see tests/test_core.py::test_sizes_match_fips204_table2).
"""

from dataclasses import dataclass

Q = 8380417          # modulus q = 2^23 - 2^13 + 1  (FIPS 204, Section 4)
N = 256              # polynomial degree n
D = 13               # dropped bits from t
SEED_BYTES = 32      # xi, the key-generation seed (Algorithm 1)
MU_BYTES = 64        # message representative mu (Algorithm 7, line 6)
MAX_CONTEXT_BYTES = 255  # |ctx| <= 255 (Algorithm 2, line 1)


@dataclass(frozen=True)
class ParamSet:
    name: str
    security_category: int   # NIST PQC security category
    classical_equiv: str
    tau: int                 # number of +/-1 in challenge polynomial c
    lam: int                 # collision strength of c~ (lambda)
    gamma1: int              # coefficient range of y
    gamma2: int              # low-order rounding range
    k: int                   # rows of matrix A
    l: int                   # columns of matrix A
    eta: int                 # private key coefficient range
    beta: int                # tau * eta
    omega: int               # max number of 1s in hint h
    pk_bytes: int            # Table 2
    sk_bytes: int            # Table 2 (expanded private key)
    sig_bytes: int           # Table 2
    oid: str                 # id-ml-dsa-* (NIST CSOR)


PARAM_SETS = {
    "ML-DSA-44": ParamSet(
        "ML-DSA-44", 2, "~SHA-256 collision / AES-128+", 39, 128,
        2**17, (Q - 1) // 88, 4, 4, 2, 78, 80, 1312, 2560, 2420,
        "2.16.840.1.101.3.4.3.17",
    ),
    "ML-DSA-65": ParamSet(
        "ML-DSA-65", 3, "~AES-192", 49, 192,
        2**19, (Q - 1) // 32, 6, 5, 4, 196, 55, 1952, 4032, 3309,
        "2.16.840.1.101.3.4.3.18",
    ),
    "ML-DSA-87": ParamSet(
        "ML-DSA-87", 5, "~AES-256", 60, 256,
        2**19, (Q - 1) // 32, 8, 7, 2, 120, 75, 2592, 4896, 4627,
        "2.16.840.1.101.3.4.3.19",
    ),
}

DEFAULT_PARAM_SET = "ML-DSA-65"
