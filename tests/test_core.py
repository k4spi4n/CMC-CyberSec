"""Functional and security tests for mldsa_app.core and the CLI."""

import base64
import io
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from mldsa_app import cli, core
from mldsa_app.params import PARAM_SETS

ALGS = list(PARAM_SETS)


@pytest.fixture(scope="module", params=ALGS)
def key(request):
    return core.generate_keypair(request.param)


@pytest.fixture(scope="module")
def key65():
    return core.generate_keypair("ML-DSA-65")


def flip_bit(data: bytes, index: int, bit: int = 0) -> bytes:
    b = bytearray(data)
    b[index] ^= 1 << bit
    return bytes(b)


# ---------------------------------------------------------------- sizes ----

def test_sizes_match_fips204_table2(key):
    p = PARAM_SETS[core.param_set_of(key)]
    assert len(key.public_key().public_bytes_raw()) == p.pk_bytes
    assert len(key.private_bytes_raw()) == 32  # seed xi
    assert len(core.sign_bytes(key, b"m")) == p.sig_bytes


def test_param_table_consistency():
    for p in PARAM_SETS.values():
        assert p.beta == p.tau * p.eta
        # pk = 32 + 32*k*(bitlen(q-1) - d)   (FIPS 204, Section 5.1)
        assert p.pk_bytes == 32 + 32 * p.k * (23 - 13)


# ------------------------------------------------------------ roundtrip ----

@pytest.mark.parametrize("msg", [b"", b"\x00", b"hello", os.urandom(5000)])
def test_sign_verify_roundtrip(key, msg):
    sig = core.sign_bytes(key, msg)
    assert core.verify_bytes(key.public_key(), msg, sig)


def test_stream_and_pure_are_interchangeable(key):
    msg = os.urandom(2 * core.CHUNK_SIZE + 5)
    s_stream = core.sign_stream(key, io.BytesIO(msg))
    s_pure = core.sign_bytes(key, msg)
    pk = key.public_key()
    assert core.verify_bytes(pk, msg, s_stream)
    assert core.verify_stream(pk, io.BytesIO(msg), s_pure)


def test_hedged_signatures_are_randomized(key65):
    msg = b"same message"
    s1, s2 = core.sign_bytes(key65, msg), core.sign_bytes(key65, msg)
    assert s1 != s2
    assert core.verify_bytes(key65.public_key(), msg, s1)
    assert core.verify_bytes(key65.public_key(), msg, s2)


def test_seed_is_deterministic():
    seed = os.urandom(32)
    a = core.key_from_seed("ML-DSA-44", seed)
    b = core.key_from_seed("ML-DSA-44", seed)
    assert a.public_key() == b.public_key()


@pytest.mark.parametrize("n", [0, 31, 33, 64])
def test_seed_wrong_length_rejected(n):
    with pytest.raises(ValueError):
        core.key_from_seed("ML-DSA-44", b"\x01" * n)


def test_unknown_param_set_rejected():
    with pytest.raises(ValueError):
        core.generate_keypair("ML-DSA-128")


# ------------------------------------------------- modified message ----

@pytest.mark.parametrize("mutate", [
    lambda m: flip_bit(m, 0),
    lambda m: flip_bit(m, len(m) - 1, 7),
    lambda m: m + b"\x00",
    lambda m: m[:-1],
    lambda m: b"",
], ids=["flip-first", "flip-last", "append", "truncate", "empty"])
def test_modified_message_rejected(key, mutate):
    msg = b"Ben A chuyen 100.000.000 VND"
    sig = core.sign_bytes(key, msg)
    assert not core.verify_bytes(key.public_key(), mutate(msg), sig)


# ----------------------------------------------- modified signature ----

def test_every_region_of_signature_is_checked(key):
    """sigEncode = c~ || z || h (Algorithm 26). Flip a bit in each region."""
    p = PARAM_SETS[core.param_set_of(key)]
    msg = b"doc"
    sig = core.sign_bytes(key, msg)
    c_tilde_len = p.lam // 4
    for idx in [0, c_tilde_len - 1, c_tilde_len, p.sig_bytes // 2, p.sig_bytes - p.omega - p.k - 1]:
        assert not core.verify_bytes(key.public_key(), msg, flip_bit(sig, idx)), idx


@pytest.mark.parametrize("mutate", [
    lambda s: s[:-1],
    lambda s: s + b"\x00",
    lambda s: b"",
    lambda s: bytes(len(s)),
    lambda s: os.urandom(len(s)),
], ids=["truncated", "extended", "empty", "all-zero", "random"])
def test_malformed_signature_rejected(key65, mutate):
    sig = core.sign_bytes(key65, b"doc")
    assert not core.verify_bytes(key65.public_key(), b"doc", mutate(sig))


def test_malformed_hint_rejected(key65):
    """Hint indices must be strictly increasing and counts <= omega (Algorithm 21)."""
    p = PARAM_SETS["ML-DSA-65"]
    sig = bytearray(core.sign_bytes(key65, b"doc"))
    sig[-p.k:] = bytes([0xFF] * p.k)  # counts > omega -> HintBitUnpack fails
    assert not core.verify_bytes(key65.public_key(), b"doc", bytes(sig))


# --------------------------------------------------------- wrong key ----

def test_wrong_key_same_param_set(key):
    other = core.generate_keypair(core.param_set_of(key))
    sig = core.sign_bytes(key, b"doc")
    assert not core.verify_bytes(other.public_key(), b"doc", sig)


def test_wrong_param_set():
    k44, k65 = core.generate_keypair("ML-DSA-44"), core.generate_keypair("ML-DSA-65")
    assert not core.verify_bytes(k65.public_key(), b"doc", core.sign_bytes(k44, b"doc"))


@pytest.mark.parametrize("alg", ALGS)
def test_public_key_wrong_length_rejected(alg):
    with pytest.raises(ValueError):
        core.public_key_from_bytes(alg, b"\x00" * (PARAM_SETS[alg].pk_bytes - 1))


# ----------------------------------------------------------- context ----

def test_context_domain_separation(key65):
    sig = core.sign_bytes(key65, b"doc", "doc-sign/v1")
    pk = key65.public_key()
    assert core.verify_bytes(pk, b"doc", sig, "doc-sign/v1")
    assert not core.verify_bytes(pk, b"doc", sig, "payment/v1")
    assert not core.verify_bytes(pk, b"doc", sig, "doc-sign/v1\x00")
    assert not core.verify_bytes(pk, b"doc", sig, "")


def test_context_length_boundary(key65):
    pk = key65.public_key()
    for n in (0, 1, 255):
        ctx = b"c" * n
        assert core.verify_bytes(pk, b"m", core.sign_bytes(key65, b"m", ctx), ctx)
    with pytest.raises(ValueError):
        core.sign_bytes(key65, b"m", b"c" * 256)
    with pytest.raises(ValueError):
        core.verify_bytes(pk, b"m", b"x", b"c" * 256)


def test_context_utf8_byte_length_counts():
    # 128 x "đ" = 256 UTF-8 bytes, although only 128 characters
    with pytest.raises(ValueError):
        core.encode_context("đ" * 128)


# ------------------------------------------------------- key storage ----

def test_encrypted_private_key_roundtrip(tmp_path, key):
    path = tmp_path / "k.pem"
    core.save_private_key(key, path, b"correct horse")
    assert b"ENCRYPTED PRIVATE KEY" in path.read_bytes()
    loaded = core.load_private_key(path, b"correct horse")
    assert loaded.private_bytes_raw() == key.private_bytes_raw()


def test_wrong_password_rejected(tmp_path, key65):
    path = tmp_path / "k.pem"
    core.save_private_key(key65, path, b"right")
    with pytest.raises(ValueError):
        core.load_private_key(path, b"wrong")
    with pytest.raises(TypeError):
        core.load_private_key(path, None)


def test_public_key_pem_roundtrip(tmp_path, key):
    path = tmp_path / "k.pub.pem"
    core.save_public_key(key.public_key(), path)
    assert core.load_public_key(path) == key.public_key()


def test_non_mldsa_key_rejected():
    ec_key = ec.generate_private_key(ec.SECP256R1())
    pem = ec_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    with pytest.raises(TypeError):
        core.load_public_key_pem(pem)


# ------------------------------------------------------------ bundle ----

@pytest.fixture
def signed_doc(tmp_path, key65):
    doc = tmp_path / "doc.txt"
    doc.write_bytes(b"Hop dong so 42")
    return doc, core.sign_file(key65, doc)


def test_bundle_valid(signed_doc, key65):
    doc, bundle = signed_doc
    assert core.verify_file(key65.public_key(), doc, bundle).ok


def test_bundle_tampered_file(signed_doc, key65):
    doc, bundle = signed_doc
    doc.write_bytes(b"Hop dong so 43")
    assert not core.verify_file(key65.public_key(), doc, bundle).ok


@pytest.mark.parametrize("field,value", [
    ("format", "other/v9"),
    ("algorithm", "ML-DSA-44"),
    ("signature_b64", "!!!not base64!!!"),
    ("signature_b64", base64.b64encode(b"short").decode()),
    ("context_b64", base64.b64encode(b"payment/v1").decode()),
    ("public_key_sha3_256", "00" * 32),
])
def test_bundle_tampered_metadata(signed_doc, key65, field, value):
    doc, bundle = signed_doc
    assert not core.verify_file(key65.public_key(), doc, dict(bundle, **{field: value})).ok


def test_bundle_missing_signature(signed_doc, key65):
    doc, bundle = signed_doc
    bundle = {k: v for k, v in bundle.items() if k != "signature_b64"}
    assert not core.verify_file(key65.public_key(), doc, bundle).ok


def test_bundle_context_relabel_attack(signed_doc, key65):
    """Changing ctx in metadata to match the verifier does not help: ctx is inside mu."""
    doc, bundle = signed_doc
    relabeled = dict(bundle, context_b64=base64.b64encode(b"payment/v1").decode())
    assert not core.verify_file(key65.public_key(), doc, relabeled, expected_ctx="payment/v1").ok


def test_bundle_from_other_key_with_spoofed_fingerprint(signed_doc, key65):
    doc, bundle = signed_doc
    mallory = core.generate_keypair("ML-DSA-65")
    forged = core.sign_file(mallory, doc)
    forged["public_key_sha3_256"] = bundle["public_key_sha3_256"]
    assert not core.verify_file(key65.public_key(), doc, forged).ok


# --------------------------------------------------------------- CLI ----

def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("MLDSA_PW", "s3cret")
    prefix = tmp_path / "alice"
    doc = tmp_path / "doc.txt"
    doc.write_text("noi dung")

    assert cli.main(["keygen", "--alg", "ML-DSA-44", "--out", str(prefix), "--password-env", "MLDSA_PW"]) == 0
    key_pem, pub_pem = f"{prefix}.key.pem", f"{prefix}.pub.pem"
    assert cli.main(["sign", str(doc), "--key", key_pem, "--password-env", "MLDSA_PW"]) == 0
    assert cli.main(["verify", str(doc), "--pub", pub_pem]) == 0
    assert cli.main(["verify", str(doc), "--pub", pub_pem, "--context", "other"]) == 1

    doc.write_text("noi dung da sua")
    assert cli.main(["verify", str(doc), "--pub", pub_pem]) == 1

    monkeypatch.setenv("MLDSA_PW", "wrong")
    assert cli.main(["sign", str(doc), "--key", key_pem, "--password-env", "MLDSA_PW"]) == 2
    out = capsys.readouterr()
    assert "[FAIL]" in out.out
