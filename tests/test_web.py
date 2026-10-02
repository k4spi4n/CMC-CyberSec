"""Web demo API tests (Flask test client)."""

import base64
import io
import json

import pytest

from mldsa_app import web


@pytest.fixture
def client():
    web.KEYRING.clear()
    web.app.config["TESTING"] = True
    with web.app.test_client() as c:
        yield c


def _keygen(client, label="Alice", alg="ML-DSA-44"):
    r = client.post("/api/keygen", data={"label": label, "alg": alg})
    assert r.status_code == 200, r.json
    return r.json


def _sign(client, label="Alice", text="hop dong", ctx="ctx/v1"):
    r = client.post("/api/sign", data={"label": label, "text": text, "context": ctx})
    assert r.status_code == 200, r.json
    return r.json


def _verify(client, bundle, label="Alice", text="hop dong", ctx="ctx/v1", **extra):
    data = {"label": label, "text": text, "context": ctx, "bundle": json.dumps(bundle), **extra}
    return client.post("/api/verify", data=data).json


def test_index_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "ML-DSA-87" in r.get_data(as_text=True)


def test_full_flow(client):
    info = _keygen(client)
    assert info["pk_bytes"] == 1312 and "BEGIN PUBLIC KEY" in info["public_pem"]
    bundle = _sign(client)
    assert _verify(client, bundle)["ok"]
    assert not _verify(client, bundle, text="hop dong!")["ok"]
    assert not _verify(client, bundle, ctx="other")["ok"]


def test_verify_with_pasted_public_pem(client):
    pem = _keygen(client)["public_pem"]
    bundle = _sign(client)
    web.KEYRING.clear()  # verifier only has the PEM
    assert _verify(client, bundle, label="", public_pem=pem)["ok"]


def test_wrong_signer(client):
    _keygen(client, "Alice")
    _keygen(client, "Mallory")
    bundle = _sign(client, label="Mallory")
    assert not _verify(client, bundle, label="Alice")["ok"]


def test_flipped_signature_bit(client):
    _keygen(client)
    bundle = _sign(client)
    sig = bytearray(base64.b64decode(bundle["signature_b64"]))
    sig[7] ^= 0x80
    bundle["signature_b64"] = base64.b64encode(bytes(sig)).decode()
    assert not _verify(client, bundle)["ok"]


def test_file_upload(client):
    _keygen(client)
    data = bytes(range(256)) * 100
    r = client.post("/api/sign", data={"label": "Alice", "context": "c",
                                        "file": (io.BytesIO(data), "blob.bin")},
                    content_type="multipart/form-data")
    bundle = r.json
    assert bundle["file_name"] == "blob.bin" and bundle["file_size"] == len(data)
    r = client.post("/api/verify", data={"label": "Alice", "context": "c", "bundle": json.dumps(bundle),
                                          "file": (io.BytesIO(data), "blob.bin")},
                    content_type="multipart/form-data")
    assert r.json["ok"]


@pytest.mark.parametrize("form,expected", [
    ({"label": "x", "alg": "RSA-2048"}, 400),
    ({"label": "<script>", "alg": "ML-DSA-44"}, 400),
    ({"label": "", "alg": "ML-DSA-44"}, 400),
])
def test_keygen_input_validation(client, form, expected):
    assert client.post("/api/keygen", data=form).status_code == expected


def test_sign_errors(client):
    assert client.post("/api/sign", data={"label": "nobody", "text": "x"}).status_code == 400
    _keygen(client)
    r = client.post("/api/sign", data={"label": "Alice", "text": "x", "context": "c" * 256})
    assert r.status_code == 400 and "255" in r.json["error"]


def test_verify_garbage_inputs(client):
    _keygen(client)
    assert not client.post("/api/verify", data={"label": "Alice", "bundle": "not json"}).json["ok"]
    assert not client.post("/api/verify", data={"label": "Alice", "bundle": "[1,2]"}).json["ok"]
    r = client.post("/api/verify", data={"public_pem": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
                                          "bundle": "{}"})
    assert r.status_code == 400


def test_export_requires_strong_password(client):
    _keygen(client)
    assert client.post("/api/export", data={"label": "Alice", "password": "short"}).status_code == 400
    r = client.post("/api/export", data={"label": "Alice", "password": "long enough pw"})
    assert "ENCRYPTED PRIVATE KEY" in r.json["pem"]
