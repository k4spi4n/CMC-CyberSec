"""Known-answer tests against official NIST ACVP vectors for FIPS 204.

Source: https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files
  - ML-DSA-keyGen-FIPS204/internalProjection.json
  - ML-DSA-sigVer-FIPS204/internalProjection.json
"""

import json
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature

from mldsa_app import core

VECTORS = Path(__file__).parent / "vectors"


def _load(name):
    return json.loads((VECTORS / name / "internalProjection.json").read_text())


def _cases(data, group_filter):
    for g in data["testGroups"]:
        if group_filter(g):
            for t in g["tests"]:
                yield pytest.param(g, t, id=f"{g['parameterSet']}-tg{g['tgId']}-tc{t['tcId']}")


KEYGEN = _load("ML-DSA-keyGen-FIPS204")
SIGVER = _load("ML-DSA-sigVer-FIPS204")


@pytest.mark.parametrize("group,test", list(_cases(KEYGEN, lambda g: True)))
def test_keygen_from_seed_matches_nist(group, test):
    """KeyGen_internal(xi) must produce exactly NIST's public key (Algorithm 6)."""
    key = core.key_from_seed(group["parameterSet"], bytes.fromhex(test["seed"]))
    assert key.public_key().public_bytes_raw() == bytes.fromhex(test["pk"])


def _pure(g):
    return g["signatureInterface"] == "external" and g["preHash"] == "pure"


def _external_mu(g):
    return g["signatureInterface"] == "internal" and g["externalMu"]


@pytest.mark.parametrize("group,test", list(_cases(SIGVER, _pure)))
def test_sigver_pure_matches_nist(group, test):
    """ML-DSA.Verify (Algorithm 3) with ctx: accept valid, reject modified msg/sig."""
    pk = core.public_key_from_bytes(group["parameterSet"], bytes.fromhex(test["pk"]))
    ok = core.verify_bytes(
        pk,
        bytes.fromhex(test["message"]),
        bytes.fromhex(test["signature"]),
        bytes.fromhex(test["context"]),
    )
    assert ok == test["testPassed"], test["reason"]


@pytest.mark.parametrize("group,test", list(_cases(SIGVER, _external_mu)))
def test_sigver_external_mu_matches_nist(group, test):
    """Verify over an externally computed mu (the path used for file streaming)."""
    pk = core.public_key_from_bytes(group["parameterSet"], bytes.fromhex(test["pk"]))
    try:
        pk.verify_mu(bytes.fromhex(test["signature"]), bytes.fromhex(test["mu"]))
        ok = True
    except InvalidSignature:
        ok = False
    assert ok == test["testPassed"], test["reason"]


def test_vector_coverage():
    """Guard against silently testing nothing (e.g. if the JSON layout changes)."""
    assert len(list(_cases(KEYGEN, lambda g: True))) == 75
    assert len(list(_cases(SIGVER, _pure))) == 45
    assert len(list(_cases(SIGVER, _external_mu))) == 45
