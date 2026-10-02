"""Interoperability with an independent FIPS 204 implementation (dilithium-py).

If two unrelated implementations derive identical keys from the same seed
and accept each other's signatures, our use of the library (context string,
external mu, key encoding) matches the standard rather than a private quirk.
"""

import io
import os

import pytest
from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87

from mldsa_app import core

REF = {"ML-DSA-44": ML_DSA_44, "ML-DSA-65": ML_DSA_65, "ML-DSA-87": ML_DSA_87}
CTX = b"CMC-CyberSec/doc-sign/v1"


@pytest.mark.parametrize("alg", list(REF))
def test_same_seed_same_public_key(alg):
    seed = os.urandom(32)
    ref_pk, _ = REF[alg].key_derive(seed)
    assert core.key_from_seed(alg, seed).public_key().public_bytes_raw() == ref_pk


@pytest.mark.parametrize("alg", list(REF))
def test_our_signature_verifies_in_reference(alg):
    seed = os.urandom(32)
    key = core.key_from_seed(alg, seed)
    msg = os.urandom(300)
    sig = core.sign_bytes(key, msg, CTX)
    ref_pk, _ = REF[alg].key_derive(seed)
    assert REF[alg].verify(ref_pk, msg, sig, ctx=CTX)
    assert not REF[alg].verify(ref_pk, msg, sig, ctx=b"other")


@pytest.mark.parametrize("alg", list(REF))
def test_streamed_signature_is_standard_signature(alg):
    """sign_stream (external mu) yields a signature over the full message."""
    seed = os.urandom(32)
    key = core.key_from_seed(alg, seed)
    msg = os.urandom(3 * core.CHUNK_SIZE + 17)
    sig = core.sign_stream(key, io.BytesIO(msg), CTX)
    ref_pk, _ = REF[alg].key_derive(seed)
    assert REF[alg].verify(ref_pk, msg, sig, ctx=CTX)


@pytest.mark.parametrize("alg", list(REF))
def test_reference_signature_verifies_in_ours(alg):
    ref_pk, ref_sk = REF[alg].keygen()
    msg = b"signed by the reference implementation"
    sig = REF[alg].sign(ref_sk, msg, ctx=CTX)
    pk = core.public_key_from_bytes(alg, ref_pk)
    assert core.verify_bytes(pk, msg, sig, CTX)
    assert core.verify_stream(pk, io.BytesIO(msg), sig, CTX)
    assert not core.verify_bytes(pk, msg + b"!", sig, CTX)
