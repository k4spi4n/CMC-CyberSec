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


def _read_password(args, confirm: bool) -> bytes | None:
    if getattr(args, "no_password", False):
        return None
    if args.password_env:
        value = os.environ.get(args.password_env)
        if value is None:
            sys.exit(f"Biến môi trường {args.password_env} chưa được đặt")
        return value.encode()
    pw = getpass.getpass("Mật khẩu khóa bí mật: ")
    if confirm and getpass.getpass("Nhập lại mật khẩu: ") != pw:
        sys.exit("Mật khẩu không khớp")
    return pw.encode() or None


def cmd_keygen(args) -> int:
    key = core.generate_keypair(args.alg)
    password = _read_password(args, confirm=True)
    if password is None:
        print("CẢNH BÁO: khóa bí mật được lưu KHÔNG mã hóa.")
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    priv_path = out.with_name(out.name + ".key.pem")
    pub_path = out.with_name(out.name + ".pub.pem")
    core.save_private_key(key, priv_path, password)
    core.save_public_key(key.public_key(), pub_path)
    p = PARAM_SETS[args.alg]
    print(f"Đã sinh cặp khóa {args.alg} (security category {p.security_category})")
    print(f"  Khóa bí mật : {priv_path}  (lưu seed xi 32 B, PKCS#8{' mã hóa' if password else ''})")
    print(f"  Khóa công khai: {pub_path}  (pk {p.pk_bytes} B)")
    print(f"  Fingerprint SHA3-256: {core.fingerprint(key.public_key())}")
    return 0


def cmd_sign(args) -> int:
    key = core.load_private_key(args.key, _read_password(args, confirm=False))
    t0 = time.perf_counter()
    bundle = core.sign_file(key, args.file, args.context)
    dt = (time.perf_counter() - t0) * 1000
    out = args.out or f"{args.file}.sig.json"
    core.save_bundle(bundle, out)
    print(f"Đã ký {args.file} bằng {bundle['algorithm']} trong {dt:.1f} ms")
    print(f"  Chữ ký: {out}  ({PARAM_SETS[bundle['algorithm']].sig_bytes} B)")
    print(f"  Context: {args.context!r}")
    return 0


def cmd_verify(args) -> int:
    pub = core.load_public_key(args.pub)
    sig_path = args.sig or f"{args.file}.sig.json"
    try:
        bundle = core.load_bundle(sig_path)
    except (OSError, ValueError) as e:
        print(f"[FAIL] Không đọc được tệp chữ ký: {e}")
        return 1
    result = core.verify_file(pub, args.file, bundle, args.context)
    tag = "[ OK ]" if result.ok else "[FAIL]"
    print(f"{tag} {result.reason}  ({result.param_set}, tệp {args.file})")
    return 0 if result.ok else 1


def cmd_info(args) -> int:
    print("Bộ tham số ML-DSA (FIPS 204, Table 1 & 2)")
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

    print(f"Benchmark ({n} lần, thông điệp 1 KiB) — thời gian trung bình ms")
    print(f"{'Thuật toán':14}{'KeyGen':>9}{'Sign':>9}{'Verify':>9}{'pk B':>7}{'sig B':>7}  Hậu lượng tử?")
    for name in PARAM_SETS:
        key = core.generate_keypair(name)
        pub = key.public_key()
        sig = core.sign_bytes(key, msg)
        print(f"{name:14}{timeit(lambda: core.generate_keypair(name)):9.2f}"
              f"{timeit(lambda: core.sign_bytes(key, msg)):9.2f}"
              f"{timeit(lambda: core.verify_bytes(pub, msg, sig)):9.2f}"
              f"{len(pub.public_bytes_raw()):7}{len(sig):7}  Có")

    ek = ec.generate_private_key(ec.SECP256R1())
    esig = ek.sign(msg, ec.ECDSA(hashes.SHA256()))
    print(f"{'ECDSA P-256':14}{timeit(lambda: ec.generate_private_key(ec.SECP256R1())):9.2f}"
          f"{timeit(lambda: ek.sign(msg, ec.ECDSA(hashes.SHA256()))):9.2f}"
          f"{timeit(lambda: ek.public_key().verify(esig, msg, ec.ECDSA(hashes.SHA256()))):9.2f}"
          f"{65:7}{len(esig):7}  Không (Shor)")

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
          f"{384:7}{len(rsig):7}  Không (Shor)")
    return 0


def cmd_demo(args) -> int:
    """Scripted end-to-end scenario for the class demo."""
    alg = args.alg
    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)
        doc = tmp / "hop_dong.txt"
        doc.write_text("Bên A chuyển cho bên B 100.000.000 VND.\n", encoding="utf-8")

        def step(title):
            print(f"\n== {title}")

        step(f"1. Alice sinh cặp khóa {alg}")
        alice = core.generate_keypair(alg)
        print(f"   pk = {len(alice.public_key().public_bytes_raw())} B, seed = 32 B, "
              f"fingerprint {core.fingerprint(alice.public_key())[:16]}...")

        step("2. Alice ký hợp đồng")
        bundle = core.sign_file(alice, doc)
        print(f"   chữ ký = {PARAM_SETS[alg].sig_bytes} B, context = {core.DEFAULT_CONTEXT!r}")

        step("3. Bob xác minh với khóa công khai của Alice")
        print("  ", core.verify_file(alice.public_key(), doc, bundle).reason)

        step("4. Ký lại cùng tài liệu -> chữ ký khác (hedged signing, FIPS 204 §3.4)")
        bundle2 = core.sign_file(alice, doc)
        print(f"   chữ ký giống nhau? {bundle2['signature_b64'] == bundle['signature_b64']}; "
              f"bản 2 hợp lệ? {core.verify_file(alice.public_key(), doc, bundle2).ok}")

        step("5. Kẻ tấn công sửa 100.000.000 -> 900.000.000")
        doc.write_text("Bên A chuyển cho bên B 900.000.000 VND.\n", encoding="utf-8")
        print("  ", core.verify_file(alice.public_key(), doc, bundle).reason)
        doc.write_text("Bên A chuyển cho bên B 100.000.000 VND.\n", encoding="utf-8")

        step("6. Lật 1 bit trong chữ ký")
        sig = bytearray(base64.b64decode(bundle["signature_b64"]))
        sig[100] ^= 0x01
        bad = dict(bundle, signature_b64=base64.b64encode(bytes(sig)).decode())
        print("  ", core.verify_file(alice.public_key(), doc, bad).reason)

        step("7. Mallory dùng khóa của mình ký, giả danh Alice")
        mallory = core.generate_keypair(alg)
        forged = core.sign_file(mallory, doc)
        forged["public_key_sha3_256"] = bundle["public_key_sha3_256"]
        print("  ", core.verify_file(alice.public_key(), doc, forged).reason)

        step("8. Dùng lại chữ ký trong ngữ cảnh khác (context = 'payment/v1')")
        print("   metadata giữ nguyên:", core.verify_file(alice.public_key(), doc, bundle, expected_ctx="payment/v1").reason)
        relabeled = dict(bundle, context_b64=base64.b64encode(b"payment/v1").decode())
        print("   sửa cả metadata    :",
              core.verify_file(alice.public_key(), doc, relabeled, expected_ctx="payment/v1").reason)

        step("9. Tệp rỗng và tệp 20 MiB (ký theo luồng, external mu)")
        empty = tmp / "empty.bin"
        empty.write_bytes(b"")
        print("   rỗng :", core.verify_file(alice.public_key(), empty, core.sign_file(alice, empty)).reason)
        big = tmp / "big.bin"
        big.write_bytes(os.urandom(20 << 20))
        t0 = time.perf_counter()
        b = core.sign_file(alice, big)
        r = core.verify_file(alice.public_key(), big, b)
        print(f"   20 MiB: {r.reason} ({(time.perf_counter() - t0):.2f} s cho ký + xác minh)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="mldsa_app", description="Ký/xác minh tài liệu bằng ML-DSA (FIPS 204)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_pw(p, allow_none):
        p.add_argument("--password-env", help="đọc mật khẩu khóa bí mật từ biến môi trường này")
        if allow_none:
            p.add_argument("--no-password", action="store_true", help="lưu khóa bí mật không mã hóa (không khuyến nghị)")

    p = sub.add_parser("keygen", help="sinh cặp khóa")
    p.add_argument("--alg", choices=list(PARAM_SETS), default=DEFAULT_PARAM_SET)
    p.add_argument("--out", required=True, help="tiền tố tên tệp, vd keys/alice")
    add_pw(p, True)
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="ký một tệp")
    p.add_argument("file")
    p.add_argument("--key", required=True)
    p.add_argument("--context", default=core.DEFAULT_CONTEXT)
    p.add_argument("--out")
    add_pw(p, False)
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="xác minh chữ ký")
    p.add_argument("file")
    p.add_argument("--pub", required=True)
    p.add_argument("--sig")
    p.add_argument("--context", default=core.DEFAULT_CONTEXT)
    p.set_defaults(func=cmd_verify)

    sub.add_parser("info", help="in bảng tham số FIPS 204").set_defaults(func=cmd_info)

    p = sub.add_parser("bench", help="đo hiệu năng, so sánh với RSA/ECDSA")
    p.add_argument("-n", type=int, default=50)
    p.set_defaults(func=cmd_bench)

    p = sub.add_parser("demo", help="chạy kịch bản demo đầy đủ")
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
        print(f"Lỗi: {e}", file=sys.stderr)
        return 2
