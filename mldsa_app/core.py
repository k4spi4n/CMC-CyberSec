"""ML-DSA (FIPS 204) document signing core.

All lattice math is delegated to `pyca/cryptography` (backed by OpenSSL).
This module only adds: parameter-set handling, key storage, streaming
("external mu") signing of files, and a JSON signature bundle.

Design notes (mapped to FIPS 204 in REPORT.md):
  * Pure ML-DSA with a context string ctx (Algorithm 2 / Algorithm 3).
  * Files are hashed in chunks into mu = H(tr || 0 || |ctx| || ctx || M, 64)
    (Algorithm 7, line 6) and signed with sign_mu. The resulting signature
    is a normal ML-DSA signature: any FIPS 204 verifier can check it against
    the whole file with the same ctx.
  * Signing is "hedged" (fresh randomness rnd per signature, Section 3.4),
    which is the default recommended by FIPS 204.
  * Private keys are stored as the 32-byte seed xi (Section 3.6.3) inside an
    encrypted PKCS#8 PEM file.
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import BinaryIO, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import mldsa

from .params import MAX_CONTEXT_BYTES, PARAM_SETS, DEFAULT_PARAM_SET

BUNDLE_FORMAT = "cmc-mldsa-signature/v1"
DEFAULT_CONTEXT = "CMC-CyberSec/doc-sign/v1"
CHUNK_SIZE = 1 << 20

_PRIVATE_CLASSES = {
    "ML-DSA-44": mldsa.MLDSA44PrivateKey,
    "ML-DSA-65": mldsa.MLDSA65PrivateKey,
    "ML-DSA-87": mldsa.MLDSA87PrivateKey,
}
_PUBLIC_CLASSES = {
    "ML-DSA-44": mldsa.MLDSA44PublicKey,
    "ML-DSA-65": mldsa.MLDSA65PublicKey,
    "ML-DSA-87": mldsa.MLDSA87PublicKey,
}

PrivateKey = Union[mldsa.MLDSA44PrivateKey, mldsa.MLDSA65PrivateKey, mldsa.MLDSA87PrivateKey]
PublicKey = Union[mldsa.MLDSA44PublicKey, mldsa.MLDSA65PublicKey, mldsa.MLDSA87PublicKey]
Context = Union[str, bytes]


# --------------------------------------------------------------------------
# Parameter sets and keys
# --------------------------------------------------------------------------

def _check_param_set(name: str) -> str:
    if name not in PARAM_SETS:
        raise ValueError(f"Unknown parameter set {name!r}; choose one of {list(PARAM_SETS)}")
    return name


def generate_keypair(param_set: str = DEFAULT_PARAM_SET) -> PrivateKey:
    """ML-DSA.KeyGen (Algorithm 1). The seed xi comes from the OS CSPRNG."""
    return _PRIVATE_CLASSES[_check_param_set(param_set)].generate()


def key_from_seed(param_set: str, seed: bytes) -> PrivateKey:
    """ML-DSA.KeyGen_internal (Algorithm 6) from a known 32-byte seed xi."""
    if len(seed) != 32:
        raise ValueError("ML-DSA seed must be exactly 32 bytes")
    return _PRIVATE_CLASSES[_check_param_set(param_set)].from_seed_bytes(seed)


def param_set_of(key: PrivateKey | PublicKey) -> str:
    for name in PARAM_SETS:
        if isinstance(key, (_PRIVATE_CLASSES[name], _PUBLIC_CLASSES[name])):
            return name
    raise TypeError(f"Not an ML-DSA key: {type(key).__name__}")


def public_key_from_bytes(param_set: str, data: bytes) -> PublicKey:
    """pkDecode (Algorithm 23) of a raw FIPS 204 public key."""
    return _PUBLIC_CLASSES[_check_param_set(param_set)].from_public_bytes(data)


def fingerprint(public_key: PublicKey) -> str:
    """SHA3-256 of the raw public key, used only to identify keys to humans."""
    return hashlib.sha3_256(public_key.public_bytes_raw()).hexdigest()


def save_private_key(key: PrivateKey, path: str | Path, password: bytes | None) -> None:
    if password:
        enc = serialization.BestAvailableEncryption(password)
    else:
        enc = serialization.NoEncryption()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, enc)
    Path(path).write_bytes(pem)


def save_public_key(key: PublicKey, path: str | Path) -> None:
    pem = key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    Path(path).write_bytes(pem)


def load_private_key_pem(data: bytes, password: bytes | None) -> PrivateKey:
    key = serialization.load_pem_private_key(data, password or None)
    param_set_of(key)  # rejects RSA/EC/etc. keys
    return key


def load_public_key_pem(data: bytes) -> PublicKey:
    key = serialization.load_pem_public_key(data)
    param_set_of(key)
    return key


def load_private_key(path: str | Path, password: bytes | None) -> PrivateKey:
    return load_private_key_pem(Path(path).read_bytes(), password)


def load_public_key(path: str | Path) -> PublicKey:
    return load_public_key_pem(Path(path).read_bytes())


# --------------------------------------------------------------------------
# Signing and verification
# --------------------------------------------------------------------------

def encode_context(ctx: Context) -> bytes:
    """ctx is an application-chosen byte string of at most 255 bytes."""
    raw = ctx.encode("utf-8") if isinstance(ctx, str) else bytes(ctx)
    if len(raw) > MAX_CONTEXT_BYTES:
        raise ValueError(f"Context string is {len(raw)} bytes; FIPS 204 allows at most {MAX_CONTEXT_BYTES}")
    return raw


def compute_mu(public_key: PublicKey, stream: BinaryIO, ctx: Context = DEFAULT_CONTEXT) -> bytes:
    """mu = H(H(pk) || 0x00 || |ctx| || ctx || M, 64), streamed over the file."""
    hasher = mldsa.MLDSAMuHasher(public_key, encode_context(ctx))
    while chunk := stream.read(CHUNK_SIZE):
        hasher.update(chunk)
    return hasher.finalize()


def sign_bytes(key: PrivateKey, message: bytes, ctx: Context = DEFAULT_CONTEXT) -> bytes:
    """ML-DSA.Sign (Algorithm 2), hedged."""
    return key.sign(message, encode_context(ctx))


def verify_bytes(public_key: PublicKey, message: bytes, signature: bytes, ctx: Context = DEFAULT_CONTEXT) -> bool:
    """ML-DSA.Verify (Algorithm 3)."""
    try:
        public_key.verify(signature, message, encode_context(ctx))
        return True
    except InvalidSignature:
        return False


def sign_stream(key: PrivateKey, stream: BinaryIO, ctx: Context = DEFAULT_CONTEXT) -> bytes:
    return key.sign_mu(compute_mu(key.public_key(), stream, ctx))


def verify_stream(public_key: PublicKey, stream: BinaryIO, signature: bytes, ctx: Context = DEFAULT_CONTEXT) -> bool:
    mu = compute_mu(public_key, stream, ctx)
    try:
        public_key.verify_mu(signature, mu)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# Signature bundle (.sig.json)
# --------------------------------------------------------------------------

@dataclass
class VerifyResult:
    ok: bool
    reason: str
    param_set: str | None = None


def sign_file(key: PrivateKey, path: str | Path, ctx: Context = DEFAULT_CONTEXT) -> dict:
    path = Path(path)
    with path.open("rb") as f:
        signature = sign_stream(key, f, ctx)
    return make_bundle(key, signature, ctx, path.name, path.stat().st_size)


def make_bundle(key: PrivateKey, signature: bytes, ctx: Context, file_name: str, file_size: int) -> dict:
    ctx_bytes = encode_context(ctx)
    # Everything except "signature" is informational metadata and is NOT
    # covered by the signature. The verifier never trusts it for security
    # decisions: the algorithm comes from the public key and ctx from the
    # verifier's own expectation.
    return {
        "format": BUNDLE_FORMAT,
        "algorithm": param_set_of(key),
        "context_b64": base64.b64encode(ctx_bytes).decode(),
        "public_key_sha3_256": fingerprint(key.public_key()),
        "file_name": file_name,
        "file_size": file_size,
        "signed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "signature_b64": base64.b64encode(signature).decode(),
    }


def save_bundle(bundle: dict, path: str | Path) -> None:
    Path(path).write_text(json.dumps(bundle, indent=2), encoding="utf-8")


def load_bundle(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_file_stream(
    public_key: PublicKey,
    stream: BinaryIO,
    bundle: dict,
    expected_ctx: Context = DEFAULT_CONTEXT,
) -> VerifyResult:
    alg = param_set_of(public_key)
    try:
        if bundle.get("format") != BUNDLE_FORMAT:
            return VerifyResult(False, "Sai định dạng tệp chữ ký", alg)
        if bundle.get("algorithm") != alg:
            return VerifyResult(
                False,
                f"Tham số không khớp: chữ ký ghi {bundle.get('algorithm')}, khóa công khai là {alg}",
                alg,
            )
        signature = base64.b64decode(bundle["signature_b64"], validate=True)
        bundle_ctx = base64.b64decode(bundle.get("context_b64", ""), validate=True)
    except (KeyError, ValueError, TypeError):
        return VerifyResult(False, "Tệp chữ ký bị hỏng (không giải mã được)", alg)

    expected = encode_context(expected_ctx)
    if bundle_ctx != expected:
        return VerifyResult(False, "Context string không khớp với ngữ cảnh mong đợi", alg)

    expected_len = PARAM_SETS[alg].sig_bytes
    if len(signature) != expected_len:
        return VerifyResult(False, f"Độ dài chữ ký {len(signature)} B, FIPS 204 yêu cầu {expected_len} B", alg)

    if not verify_stream(public_key, stream, signature, expected):
        if bundle.get("public_key_sha3_256") != fingerprint(public_key):
            return VerifyResult(False, "Chữ ký KHÔNG hợp lệ (có thể được ký bằng khóa khác)", alg)
        return VerifyResult(False, "Chữ ký KHÔNG hợp lệ: tệp hoặc chữ ký đã bị sửa", alg)

    if bundle.get("public_key_sha3_256") != fingerprint(public_key):
        return VerifyResult(False, "Metadata không nhất quán: dấu vân tay khóa sai", alg)
    return VerifyResult(True, "Chữ ký HỢP LỆ", alg)


def verify_file(
    public_key: PublicKey,
    path: str | Path,
    bundle: dict,
    expected_ctx: Context = DEFAULT_CONTEXT,
) -> VerifyResult:
    with Path(path).open("rb") as f:
        return verify_file_stream(public_key, f, bundle, expected_ctx)
