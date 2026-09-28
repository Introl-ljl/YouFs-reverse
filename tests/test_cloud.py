"""Cloud wire-format regressions: the sign and payload-key algorithms.

These lock in two derivations that were expensive to recover, using the
app's own captured requests as fixed vectors. If either regresses, every
third-party request starts failing with a server-side validation error that
does not name the offending field.
"""

import base64
import gzip
import hashlib
import hmac
import json
import os
import string

import pytest

from youfs.cloud import (KEY4, SIGN_FIELDS, _swap, compute_sign,
                         payload_enc_key, wire_api_name)

CAP = os.path.join("work", "mumu", "captures")

# The captured app session used these ecode values (one per login); the
# responses decrypt under exactly one of them.
ECODE_CANDS = [f"sess0000{d}0000000" for d in string.hexdigits[:16]]


def _load_capture(prefix, kind="req"):
    """Read <prefix>_req_<api>.json / <prefix>_resp.json if present."""
    if not os.path.isdir(CAP):
        pytest.skip("capture corpus not present")
    for name in os.listdir(CAP):
        if name.startswith(f"{prefix}_{kind}_") or name == f"{prefix}_{kind}.json":
            return json.load(open(os.path.join(CAP, name), encoding="utf-8"))
    pytest.skip(f"capture {prefix}_{kind} not present")


def _decrypt(b64, request_id, ecode):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    msg = KEY4 if not ecode else KEY4 + b"_" + ecode.encode()
    key = hmac.new(request_id.encode(), msg,
                   hashlib.sha256).hexdigest()[:16].encode()
    blob = base64.b64decode(b64)
    plain = AESGCM(key).decrypt(blob[:12], blob[12:], None)
    if plain[:2] == b"\x1f\x8b":
        plain = gzip.decompress(plain)
    return plain.decode("utf-8")


def test_wire_api_name_rewrites_thing_prefix():
    assert wire_api_name("thing.m.device.get") == "smartlife.m.device.get"
    assert wire_api_name("smartlife.m.device.get") == "smartlife.m.device.get"
    assert wire_api_name("m.life.location.get") == "m.life.location.get"


def test_postdata_swap_is_field_order_dependent():
    # swap() = h[8:16] + h[0:8] + h[24:32] + h[16:24]
    h = "00112233445566778899aabbccddeeff"
    assert _swap(h) == h[8:16] + h[0:8] + h[24:32] + h[16:24]
    assert _swap(h) == "4455667700112233ccddeeff8899aabb"


@pytest.mark.parametrize("prefix", ["016", "042", "045", "048", "050"])
def test_signature_reproduced_on_captured_requests(prefix):
    """The signature formula must reproduce the app's own captured sign."""
    cap = _load_capture(prefix)
    form = cap["form"]
    assert form.get("et") == "3"
    assert compute_sign(form) == form["sign"], (
        f"sign mismatch for {prefix} {form.get('a')}")


def test_payload_key_uses_request_id_as_hmac_key():
    """enc_key = HMAC-SHA256(key=requestId, msg=key4[+'_'+ecode]).hexdigest()[:16].

    Note the argument order is the reverse of the signature HMAC; getting it
    backwards still produces a plausible 16-char key that decrypts nothing.
    """
    rid = "ec668b4c-3a4d-4d45-a0ac-722712ab9155"
    expected = hmac.new(rid.encode(), KEY4, hashlib.sha256).hexdigest()[:16]
    assert payload_enc_key(rid).decode() == expected
    swapped = hmac.new(KEY4, rid.encode(), hashlib.sha256).hexdigest()[:16]
    assert payload_enc_key(rid).decode() != swapped

    with_ecode = payload_enc_key(rid, "sess000010000000")
    want = hmac.new(rid.encode(), KEY4 + b"_sess000010000000",
                    hashlib.sha256).hexdigest()[:16].encode()
    assert with_ecode == want


def test_sign_fields_exclude_gid():
    """gid travels as a top-level form field, so it must stay out of the sign."""
    assert "gid" not in SIGN_FIELDS


def test_captured_session_response_decrypts_under_one_ecode():
    """Response decryption needs the session ecode, recovered by brute force."""
    req = _load_capture("005")
    resp = _load_capture("005", "resp")
    rid = req["form"]["requestId"]
    body = json.loads(resp["body"])
    if not isinstance(body.get("result"), str):
        pytest.skip("capture response is plaintext")

    plain = None
    for ec in ECODE_CANDS:
        try:
            plain = _decrypt(body["result"], rid, ec)
            break
        except Exception:
            continue
    assert plain, "no ecode candidate decrypted the captured response"
    data = json.loads(plain)
    assert data.get("success") is True
    # the batch payload names the real device-list sub-API
    apis = [a["a"] for a in data.get("result") or []]
    assert "m.life.my.group.device.list" in apis
