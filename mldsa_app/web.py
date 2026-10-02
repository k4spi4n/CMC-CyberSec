"""Local web demo: python -m mldsa_app.web  ->  http://127.0.0.1:5000

DEMO ONLY: generated private keys live in this process's memory so the
class demo does not need to shuffle PEM files around. Bind to localhost.
"""

from __future__ import annotations

import io
import json
import re

from cryptography.hazmat.primitives import serialization
from flask import Flask, jsonify, render_template, request

from . import core
from .params import PARAM_SETS

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024

KEYRING: dict[str, core.PrivateKey] = {}
LABEL_RE = re.compile(r"^[\w\- ]{1,32}$")


def _key_info(label, key):
    alg = core.param_set_of(key)
    p = PARAM_SETS[alg]
    return {
        "label": label,
        "alg": alg,
        "category": p.security_category,
        "fingerprint": core.fingerprint(key.public_key()),
        "pk_bytes": p.pk_bytes,
        "sig_bytes": p.sig_bytes,
        "public_pem": key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode(),
    }


def _message():
    """Message comes either from an uploaded file or from the text box."""
    f = request.files.get("file")
    if f and f.filename:
        data = f.read()
        return data, f.filename
    return request.form.get("text", "").encode("utf-8"), "text.txt"


def _error(msg, code=400):
    return jsonify({"error": msg}), code


@app.get("/")
def index():
    return render_template("index.html", params=PARAM_SETS.values(), default_ctx=core.DEFAULT_CONTEXT)


@app.get("/api/keys")
def list_keys():
    return jsonify([_key_info(l, k) for l, k in KEYRING.items()])


@app.post("/api/keygen")
def keygen():
    alg = request.form.get("alg", "")
    label = request.form.get("label", "").strip()
    if alg not in PARAM_SETS:
        return _error("Bộ tham số không hợp lệ")
    if not LABEL_RE.match(label):
        return _error("Tên khóa chỉ gồm chữ, số, '-', tối đa 32 ký tự")
    KEYRING[label] = core.generate_keypair(alg)
    return jsonify(_key_info(label, KEYRING[label]))


@app.post("/api/export")
def export_private():
    key = KEYRING.get(request.form.get("label", ""))
    password = request.form.get("password", "").encode()
    if key is None:
        return _error("Không có khóa này")
    if len(password) < 8:
        return _error("Mật khẩu tối thiểu 8 ký tự")
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(password),
    )
    return jsonify({"pem": pem.decode()})


@app.post("/api/sign")
def sign():
    key = KEYRING.get(request.form.get("label", ""))
    if key is None:
        return _error("Chọn khóa bí mật để ký")
    data, name = _message()
    ctx = request.form.get("context", core.DEFAULT_CONTEXT)
    try:
        signature = core.sign_stream(key, io.BytesIO(data), ctx)
    except ValueError as e:
        return _error(str(e))
    return jsonify(core.make_bundle(key, signature, ctx, name, len(data)))


@app.post("/api/verify")
def verify():
    pub_pem = request.form.get("public_pem", "").strip()
    try:
        if pub_pem:
            pub = core.load_public_key_pem(pub_pem.encode())
        elif request.form.get("label") in KEYRING:
            pub = KEYRING[request.form["label"]].public_key()
        else:
            return _error("Chọn khóa công khai để xác minh")
    except (ValueError, TypeError):
        return _error("Khóa công khai PEM không hợp lệ hoặc không phải ML-DSA")
    try:
        bundle = json.loads(request.form.get("bundle", ""))
        if not isinstance(bundle, dict):
            raise ValueError
    except ValueError:
        return jsonify({"ok": False, "reason": "Tệp chữ ký không phải JSON hợp lệ"})
    data, _ = _message()
    try:
        r = core.verify_file_stream(pub, io.BytesIO(data), bundle, request.form.get("context", ""))
    except ValueError as e:
        return _error(str(e))
    return jsonify({"ok": r.ok, "reason": r.reason, "alg": r.param_set,
                    "fingerprint": core.fingerprint(pub)})


def main():
    app.run(host="127.0.0.1", port=5000, debug=False)


if __name__ == "__main__":
    main()
