"""Command-line interface: python -m mldsa_app <command> ..."""

from __future__ import annotations

import argparse
import base64
import getpass
import io
import os
import sys
import tempfile
import time
from pathlib import Path

from . import core
from .params import DEFAULT_PARAM_SET, PARAM_SETS

CONTRACT = "Party A transfers {} VND to Party B.\n"


def _read_password(args, confirm: bool) -> bytes | None:
    if getattr(args, "no_password", False):
        return None
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value is None:
            sys.exit(f"Environment variable {args.password_env} is not set")
        return value.encode()
    pw = getpass.getpass("Private key password: ")
    if confirm and getpass.getpass("Repeat password: ") != pw:
        sys.exit("Passwords do not match")
    return pw.encode() or None


def cmd_keygen(args) -> int:
    key = core.generate_keypair(args.alg)
    password = _read_password(args, confirm=True)
    if password is None:
        print("WARNING: the private key is stored UNENCRYPTED.")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    priv_path = out.with_name(out.name + ".key.pem")
    pub_path = out.with_name(out.name + ".pub.pem")
    core.save_private_key(key, priv_path, password)
    core.save_public_key(key.public_key(), pub_path)
    p = PARAM_SETS[args.alg]
    print(f"Generated {args.alg} key pair (security category {p.security_category})")
    print(f"  Private key: {priv_path}  (32 B seed xi, {'encrypted ' if password else ''}PKCS#8)")
    print(f"  Public key : {pub_path}  (pk {p.pk_bytes} B)")
    print(f"  SHA3-256 fingerprint: {core.fingerprint(key.public_key())}")
    return 0


def cmd_sign(args) -> int:
    key = core.load_private_key(args.key, _read_password(args, confirm=False))
    t0 = time.perf_counter()
    bundle = core.sign_file(key, args.file, args.context)
    dt = (time.perf_counter() - t0) * 1000
    out = args.out or f"{args.file}.sig.json"
    core.save_bundle(bundle, out)
    print(f"Signed {args.file} with {bundle['algorithm']} in {dt:.1f} ms")
    print(f"  Signature: {out}  ({PARAM_SETS[bundle['algorithm']].sig_bytes} B)")
    print(f"  Context: {args.context!r}")
    return 0


def cmd_verify(args) -> int:
    pub = core.load_public_key(args.pub)
    sig_path = args.sig or f"{args.file}.sig.json"
    try:
        bundle = core.load_bundle(sig_path)
    except (OSError, ValueError) as e:
        print(f"[FAIL] Cannot read signature file: {e}")
        return 1
    result = core.verify_file(pub, args.file, bundle, args.context)
    tag = "[ OK ]" if result.ok else "[FAIL]"
    print(f"{tag} {result.reason}  ({result.param_set}, file {args.file})")
    return 0 if result.ok else 1


def cmd_info(args) -> int:
    print("ML-DSA parameter sets (FIPS 204, Table 1 & 2)")
    hdr = f"{'':10}{'Cat':>4}{'(k,l)':>7}{'eta':>4}{'tau':>4}{'gamma1':>8}{'gamma2':>8}{'omega':>6}{'pk':>6}{'sk':>6}{'sig':>6}"
    print(hdr)
    for p in PARAM_SETS.values():
        print(f"{p.name:10}{p.security_category:>4}{f'({p.k},{p.l})':>7}{p.eta:>4}{p.tau:>4}"
              f"{p.gamma1:>8}{p.gamma2:>8}{p.omega:>6}{p.pk_bytes:>6}{p.sk_bytes:>6}{p.sig_bytes:>6}")
    return 0


def cmd_bench(args) -> int:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

    msg = os.urandom(1024)
    n = args.n

    def timeit(fn):
        t0 = time.perf_counter()
        for _ in range(n):
            fn()
        return (time.perf_counter() - t0) * 1000 / n

    print(f"Benchmark ({n} runs, 1 KiB message) — mean time in ms")
    print(f"{'Algorithm':14}{'KeyGen':>9}{'Sign':>9}{'Verify':>9}{'pk B':>7}{'sig B':>7}  Post-quantum?")
    for name in PARAM_SETS:
        key = core.generate_keypair(name)
        pub = key.public_key()
        sig = core.sign_bytes(key, msg)
        print(f"{name:14}{timeit(lambda: core.generate_keypair(name)):9.2f}"
              f"{timeit(lambda: core.sign_bytes(key, msg)):9.2f}"
              f"{timeit(lambda: core.verify_bytes(pub, msg, sig)):9.2f}"
              f"{len(pub.public_bytes_raw()):7}{len(sig):7}  Yes")

    ek = ec.generate_private_key(ec.SECP256R1())
    esig = ek.sign(msg, ec.ECDSA(hashes.SHA256()))
    print(f"{'ECDSA P-256':14}{timeit(lambda: ec.generate_private_key(ec.SECP256R1())):9.2f}"
          f"{timeit(lambda: ek.sign(msg, ec.ECDSA(hashes.SHA256()))):9.2f}"
          f"{timeit(lambda: ek.public_key().verify(esig, msg, ec.ECDSA(hashes.SHA256()))):9.2f}"
          f"{65:7}{len(esig):7}  No (Shor)")

    rk = rsa.generate_private_key(65537, 3072)
    pss = padding.PSS(padding.MGF1(hashes.SHA256()), padding.PSS.DIGEST_LENGTH)
    rsig = rk.sign(msg, pss, hashes.SHA256())
    rsa_n = max(1, n // 10)
    t0 = time.perf_counter()
    for _ in range(rsa_n):
        rsa.generate_private_key(65537, 3072)
    rsa_kg = (time.perf_counter() - t0) * 1000 / rsa_n
    print(f"{'RSA-3072 PSS':14}{rsa_kg:9.2f}"
          f"{timeit(lambda: rk.sign(msg, pss, hashes.SHA256())):9.2f}"
          f"{timeit(lambda: rk.public_key().verify(rsig, msg, pss, hashes.SHA256())):9.2f}"
          f"{384:7}{len(rsig):7}  No (Shor)")
    return 0


def cmd_demo(args) -> int:
    """Scripted end-to-end scenario for the class demo."""
    alg = args.alg
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        doc = tmp / "contract.txt"
        doc.write_text(CONTRACT.format("100,000,000"), encoding="utf-8")

        def step(title):
            print(f"\n== {title}")

        step(f"1. Alice generates an {alg} key pair")
        alice = core.generate_keypair(alg)
        print(f"   pk = {len(alice.public_key().public_bytes_raw())} B, seed = 32 B, "
              f"fingerprint {core.fingerprint(alice.public_key())[:16]}...")

        step("2. Alice signs the contract")
        bundle = core.sign_file(alice, doc)
        print(f"   signature = {PARAM_SETS[alg].sig_bytes} B, context = {core.DEFAULT_CONTEXT!r}")

        step("3. Bob verifies with Alice's public key")
        print("  ", core.verify_file(alice.public_key(), doc, bundle).reason)

        step("4. Sign the same document again -> different signature (hedged signing, FIPS 204 §3.4)")
        bundle2 = core.sign_file(alice, doc)
        print(f"   signatures identical? {bundle2['signature_b64'] == bundle['signature_b64']}; "
              f"second one valid? {core.verify_file(alice.public_key(), doc, bundle2).ok}")

        step("5. Attacker changes 100,000,000 -> 900,000,000")
        doc.write_text(CONTRACT.format("900,000,000"), encoding="utf-8")
        print("  ", core.verify_file(alice.public_key(), doc, bundle).reason)
        doc.write_text(CONTRACT.format("100,000,000"), encoding="utf-8")

        step("6. Flip 1 bit in the signature")
        sig = bytearray(base64.b64decode(bundle["signature_b64"]))
        sig[100] ^= 0x01
        bad = dict(bundle, signature_b64=base64.b64encode(bytes(sig)).decode())
        print("  ", core.verify_file(alice.public_key(), doc, bad).reason)

        step("7. Mallory signs with their own key, pretending to be Alice")
        mallory = core.generate_keypair(alg)
        forged = core.sign_file(mallory, doc)
        forged["public_key_sha3_256"] = bundle["public_key_sha3_256"]
        print("  ", core.verify_file(alice.public_key(), doc, forged).reason)

        step("8. Reuse the signature in another context (context = 'payment/v1')")
        print("   metadata unchanged :",
              core.verify_file(alice.public_key(), doc, bundle, expected_ctx="payment/v1").reason)
        relabeled = dict(bundle, context_b64=base64.b64encode(b"payment/v1").decode())
        print("   metadata rewritten :",
              core.verify_file(alice.public_key(), doc, relabeled, expected_ctx="payment/v1").reason)

        step("9. Empty file and 20 MiB file (streaming signing, external mu)")
        empty = tmp / "empty.bin"
        empty.write_bytes(b"")
        print("   empty :", core.verify_file(alice.public_key(), empty, core.sign_file(alice, empty)).reason)
        big = tmp / "big.bin"
        big.write_bytes(os.urandom(20 << 20))
        t0 = time.perf_counter()
        b = core.sign_file(alice, big)
        r = core.verify_file(alice.public_key(), big, b)
        print(f"   20 MiB: {r.reason} ({(time.perf_counter() - t0):.2f} s to sign + verify)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="mldsa_app", description="Sign/verify documents with ML-DSA (FIPS 204)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_pw(p, allow_none):
        p.add_argument("--password-env", help="read the private key password from this environment variable")
        if allow_none:
            p.add_argument("--no-password", action="store_true", help="store the private key unencrypted (not recommended)")

    p = sub.add_parser("keygen", help="generate a key pair")
    p.add_argument("--alg", choices=list(PARAM_SETS), default=DEFAULT_PARAM_SET)
    p.add_argument("--out", required=True, help="file name prefix, e.g. keys/alice")
    add_pw(p, True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="sign a file")
    p.add_argument("file")
    p.add_argument("--key", required=True)
    p.add_argument("--context", default=core.DEFAULT_CONTEXT)
    p.add_argument("--out")
    add_pw(p, False)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verify a signature")
    p.add_argument("file")
    p.add_argument("--pub", required=True)
    p.add_argument("--sig")
    p.add_argument("--context", default=core.DEFAULT_CONTEXT)
    p.set_defaults(func=cmd_verify)

    sub.add_parser("info", help="print the FIPS 204 parameter table").set_defaults(func=cmd_info)

    p = sub.add_parser("bench", help="measure performance, compare with RSA/ECDSA")
    p.add_argument("-n", type=int, default=50)
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("demo", help="run the full demo scenario")
    p.add_argument("--alg", choices=list(PARAM_SETS), default=DEFAULT_PARAM_SET)
    p.set_defaults(func=cmd_demo)
    return ap


def main(argv=None) -> int:
    if isinstance(sys.stdout, io.TextIOWrapper):
        sys.stdout.reconfigure(encoding="utf-8")
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except (ValueError, TypeError, OSError) as e:
        print(f"Error: {e}", file=sys.stderr)
        return 2
