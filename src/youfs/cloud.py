"""YouFs / Tuya cloud client — app-API login with the user's own credentials.

Every value below is verified against the live gateway (2026-09-28):
  - request sign: 27/27 captured app requests reproduced exactly
  - response decryption: 9/9 captured session-free responses + live calls
  - token.get returns a real RSA login token

Wire details (evidence in docs/cloud_api.md §3-§6, work/so/emulate_docmd.py):

  key4 = package + "_" + SHA256(certDER) uppercase colon hex + "_"
         + bmp_key0 + "_" + appSecret                 (native cmd0, verified)

  request sign (ThingApiSignManager.generateSignatureSdk):
      msg  = sorted whitelist fields, "k=v" joined by "||"
      postData value replaced by swap(md5hex(postData ciphertext as sent))
      swap = h[8:16]+h[0:8]+h[24:32]+h[16:24]
      sign = HMAC-SHA256(key4, msg).hexdigest()

  request/response payload key (native getEncryptoKey):
      enc_key = HMAC-SHA256(key=requestId, msg=key4 [+ "_" + ecode])
                .hexdigest()[:16]  -> 16 ASCII chars used as AES-128 key
      NOTE the argument order: requestId is the HMAC key, key4 is the message.

  postData  = base64(nonce12 || AES-128-GCM(plain) || tag16)
  response  = base64(nonce12 || AES-128-GCM(ct) || tag16) -> gzip -> JSON

Credentials come from a local file you create (never paste into chat):
    YOFS_USER=+8613800000000   (or email)
    YOFS_PASS=xxxxxxxx
    YOFS_REGION=CN             # CN | AZ | EU | IN — where your account lives
    YOFS_CC=86                 # country calling code for phone login
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import hmac
import json
import os
import secrets
import time
import urllib.parse
import urllib.request
import uuid
from typing import Any, Dict, List, Optional, Tuple

APP_KEY = "vrx3vx5nan54x8w9sx44"
APP_SECRET = "vtk5vjye4vss4shmwahxxngectfe8uqg"
PACKAGE = "com.yongfengshun"
APP_VERSION = "1.0.3"
SDK_VERSION = "5.8.0"
DEVICE_CORE_VERSION = "5.5.0"
APP_RN_VERSION = "5.79"
CHANNEL = "oem"
ET = "3"
BMP_KEY0 = "yvu7g9mgnjphc5sqv7hc9eh9ryraxmfv"

CERT_SHA256_COLON = ("A3:55:F5:F8:2C:AC:E6:07:09:86:2C:66:22:C7:5F:CD:"
                     "3C:4B:F7:46:60:BF:58:65:E0:44:A0:25:CF:29:E2:D4")

KEY4 = "_".join([PACKAGE, CERT_SHA256_COLON, BMP_KEY0, APP_SECRET]).encode()

SIGN_FIELDS = {"a", "v", "lat", "lon", "lang", "deviceId", "appVersion", "ttid",
               "isH5", "h5Token", "os", "clientId", "postData", "time",
               "requestId", "et", "n4h5", "sid", "chKey", "sp"}

REGION_API = {
    "CN": "https://a1-cn.gdyoufs.com",
    "AZ": "https://a1-us.gdyoufs.com",
    "EU": "https://a1-eu.gdyoufs.com",
    "IN": "https://a1-in.gdyoufs.com",
}

USER_AGENT = "TuyaThing/1.0.3 (com.yongfengshun)"

CH_KEY = "3fc2a062"  # native getChKey output for this app (observed)


def ttid_value() -> str:
    return f"sdk_thing@{APP_KEY}"


def wire_api_name(api: str) -> str:
    """ThingApiParams.checkAPIName(): thing.m.x -> smartlife.m.x"""
    if api.startswith("thing"):
        return "smartlife" + api[len("thing"):]
    return api


def load_secrets(path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def payload_enc_key(request_id: str, ecode: Optional[str] = None) -> bytes:
    """Native getEncryptoKey: HMAC-SHA256(key=requestId, msg=key4[_+ecode]),
    hexdigest truncated to 16 ASCII chars (used directly as the AES-128 key)."""
    msg = KEY4 if not ecode else KEY4 + b"_" + ecode.encode()
    return hmac.new(request_id.encode(), msg, hashlib.sha256).hexdigest()[:16].encode()


def _swap(h: str) -> str:
    return h[8:16] + h[0:8] + h[24:32] + h[16:24]


def compute_sign(params: Dict[str, str]) -> str:
    items = []
    for k in sorted(params):
        if k not in SIGN_FIELDS or k == "sign":
            continue
        v = params.get(k) or ""
        if not v:
            continue
        if k == "postData":
            v = _swap(hashlib.md5(v.encode()).hexdigest())
        items.append(f"{k}={v}")
    return hmac.new(KEY4, "||".join(items).encode(),
                    hashlib.sha256).hexdigest()


class TuyaCloudClient:
    def __init__(self, region: str = "CN", ttid: Optional[str] = None,
                 lang: str = "zh_Hans_CN", timeout: float = 20.0,
                 device_id: Optional[str] = None) -> None:
        if region not in REGION_API:
            raise ValueError(f"region must be one of {list(REGION_API)}")
        self.region = region
        self.base = REGION_API[region]
        self.lang = lang
        self.timeout = timeout
        self.device_id = device_id or secrets.token_hex(24)
        self.session: Optional[str] = None
        self.ecode: Optional[str] = None
        self.user: Optional[Dict[str, Any]] = None
        self.home_id: Optional[int] = None

    # ---- low level ---------------------------------------------------------

    def _base_params(self) -> Dict[str, str]:
        return {
            "clientId": APP_KEY,
            "os": "Android",
            "appVersion": APP_VERSION,
            "lang": self.lang,
            "sdkVersion": SDK_VERSION,
            "ttid": ttid_value(),
            "osSystem": "12",
            "platform": "SDY-AN00",
            "requestId": str(uuid.uuid4()),
            "timeZoneId": "Asia/Shanghai",
            "et": ET,
            "channel": CHANNEL,
            "nd": "1",
            "appRnVersion": APP_RN_VERSION,
            "deviceCoreVersion": DEVICE_CORE_VERSION,
            "chKey": CH_KEY,
            "deviceId": self.device_id,
            "time": str(int(time.time())),
            "bizData": json.dumps({"customDomainSupport": "1",
                                   "neutralDomains": "1"},
                                  separators=(",", ":")),
        }

    def request(self, api: str, version: str, post: Dict[str, Any],
                session_require: bool = False,
                form: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Signed call to /api.json.

        `post` becomes the encrypted postData body. `form` adds plain
        top-level form fields — the SDK's ApiParams.setGid() path sends gid
        that way (observed in captures: batch.invoke / scene.homepage.rule.list
        carry `gid=123456789` at form level, and gid is NOT in SIGN_FIELDS, so
        it does not affect the signature)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        params = self._base_params()
        params["a"] = wire_api_name(api)
        params["v"] = version
        for k, v in (form or {}).items():
            if v is not None:
                params[k] = str(v)
        ecode = self.ecode if session_require else None
        if session_require and self.session:
            params["sid"] = self.session
        enc_key = payload_enc_key(params["requestId"], ecode)
        nonce = os.urandom(12)
        plain = json.dumps(post, separators=(",", ":")).encode()
        params["postData"] = base64.b64encode(
            nonce + AESGCM(enc_key).encrypt(nonce, plain, None)).decode()
        params["cp"] = "gzip"
        params["sign"] = compute_sign(params)

        body = urllib.parse.urlencode(params).encode()
        req = urllib.request.Request(
            self.base + "/api.json", data=body,
            headers={"User-Agent": USER_AGENT, "Connection": "keep-alive",
                     "Content-Type": "application/x-www-form-urlencoded"})
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
        if isinstance(payload.get("result"), str) and payload.get("sign"):
            # encrypted wrapper {t, sign, result}; success lives inside
            payload = self._decrypt_response(payload["result"], enc_key)
        if payload.get("success") is True:
            return {"success": True, "result": payload.get("result")}
        return {"success": False, "raw": payload}

    @staticmethod
    def _decrypt_response(result_b64: str, enc_key: bytes) -> Any:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        blob = base64.b64decode(result_b64)
        nonce, ct = blob[:12], blob[12:]
        plain = AESGCM(enc_key).decrypt(nonce, ct, None)
        if plain[:2] == b"\x1f\x8b":
            plain = gzip.decompress(plain)
        return json.loads(plain.decode("utf-8"))

    # ---- login -------------------------------------------------------------

    def login_password(self, country_code: str, username: str,
                       password: str) -> Dict[str, Any]:
        # The wire field is the bare subscriber number: "+8613800000000" with
        # countryCode=86 is rejected as USER_PASSWD_WRONG (observed).
        if "@" not in username:
            username = username.lstrip("+")
            if username.startswith(country_code):
                username = username[len(country_code):]

        token_resp = self.request("thing.m.user.username.token.get", "2.0", {
            "countryCode": country_code,
            "username": username,
            "isUid": False,
        })
        if not token_resp["success"]:
            return {"step": "token.get", **token_resp}
        token = token_resp["result"]
        # LoginRepository builds an RSA key but Cipher.getBlockSize()==0 for
        # RSA on Android (Conscrypt) makes the block loop raise, so the app
        # falls back to: passwd = md5(password) lowercase hex, ifencrypt = 0.
        # (Verified live: RSA variants are rejected with USER_PASSWD_WRONG.)
        passwd_field = hashlib.md5(password.encode("utf-8")).hexdigest()

        if "@" in username:
            api, ver = "thing.m.user.email.password.login", "3.0"
            post = {"countryCode": country_code, "email": username,
                    "passwd": passwd_field}  # email path: same fallback
        else:
            api, ver = "thing.m.user.mobile.passwd.login", "4.0"
            post = {"countryCode": country_code, "mobile": username,
                    "passwd": passwd_field,
                    "options": '{"group": 1,"mfaCode": ""}',
                    "token": token.get("token") or "",
                    "ifencrypt": 0}
        resp = self.request(api, ver, post)
        if resp.get("success"):
            self._absorb_user(resp.get("result"))
        return resp

    def _absorb_user(self, user: Any) -> None:
        if not isinstance(user, dict):
            return
        self.user = user
        inner = user.get("result") if isinstance(user.get("result"), dict) else user
        for k in ("session", "mSession", "sid", "mt"):
            v = inner.get(k)
            if isinstance(v, str) and len(v) > 8:
                self.session = v
                break
        for k in ("ecode", "eCode"):
            v = inner.get(k)
            if isinstance(v, str) and v:
                self.ecode = v
                break
        for k in ("gid", "homeId", "defaultHomeId"):
            v = inner.get(k)
            if v not in (None, "", 0, "0"):
                try:
                    self.home_id = int(v)
                except (TypeError, ValueError):
                    pass
                break

    # ---- devices -----------------------------------------------------------

    def list_homes(self) -> Any:
        """Home/group list — the source of the homeId the device list needs."""
        return self.request("m.life.group.location.list", "7.0", {},
                            session_require=True)

    def list_devices(self, home_id: Optional[int] = None) -> Any:
        """Devices bound to a home, with localKey.

        The API the app actually uses is `m.life.my.group.device.list v2.2`
        with postData {"gid": <number>} — read from the decrypted body of the
        app's own smartlife.m.api.batch.invoke request, whose sub-call list
        names it directly (work/mumu/decrypted/, work/dec_batch_params.py).

        `m.life.app.smart.local.device.list v1.1` (the obvious-looking name,
        and what the SDK's ThingHomeBusiness calls) returns 200 with an EMPTY
        result for this account — verified against the app's own captured
        response, which is also {"result":{}}. Do not use it."""
        hid = home_id if home_id is not None else self.home_id
        if hid is None:
            return {"success": False, "error": "no homeId; call resolve_home()"}
        return self.request("m.life.my.group.device.list", "2.2",
                            {"gid": int(hid)}, session_require=True)

    def list_meshes(self, home_id: Optional[int] = None) -> Any:
        """BLE mesh keys (networkKey/appKey/localKey/srand) for the home."""
        hid = home_id if home_id is not None else self.home_id
        if hid is None:
            return {"success": False, "error": "no homeId; call resolve_home()"}
        return self.request("m.life.my.group.mesh.list", "3.1",
                            {"gid": int(hid)}, session_require=True)

    def batch_invoke(self, calls: List[Tuple[str, str, Dict[str, Any]]],
                     gid: Optional[int] = None) -> Any:
        """smartlife.m.api.batch.invoke — several sub-APIs in one signed call.

        Each sub-call is signed exactly like a full request: ApiBean.initSign()
        (network/bean/ApiBean.java:27) merges the common url params, the sub
        request body and `time`, then calls the same generateSignature(). So
        the sub `sign` covers deviceId/sid/chKey/... plus a/v/et/requestId,
        with the sub's encrypted blob supplied under the key `postData`.

        Verified byte-exact against the app's captured sub-call
        (work/verify_subsign.py: MATCH on m.life.my.group.device.list)."""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        hid = gid if gid is not None else self.home_id
        common = self._base_params()
        if self.session:
            common["sid"] = self.session
        apis = []
        for api, ver, params in calls:
            sub_rid = str(uuid.uuid4())
            enc_key = payload_enc_key(sub_rid, self.ecode)
            nonce = os.urandom(12)
            blob = nonce + AESGCM(enc_key).encrypt(
                nonce, json.dumps(params, separators=(",", ":")).encode(), None)
            blob_b64 = base64.b64encode(blob).decode()
            sub = dict(common)
            sub.update({
                "a": wire_api_name(api), "v": ver, "et": ET,
                "requestId": sub_rid, "postData": blob_b64,
                "time": str(int(time.time())),
            })
            apis.append({"a": sub["a"], "v": ver, "et": ET,
                         "requestId": sub_rid, "params": blob_b64,
                         "sign": compute_sign(sub), "t": int(sub["time"])})
        return self.request("smartlife.m.api.batch.invoke", "1.0",
                            {"apis": apis, "gid": int(hid)},
                            session_require=True)

    def check_session(self) -> bool:
        """Cheap probe: is the stored sid still accepted by the gateway?

        Uses user.info.get (session-required, no side effects). Any failure
        means the session is unusable and a fresh login is warranted — but a
        *successful* probe means we must NOT log in again: every login mints a
        new server-side session, and doing that per process is both wasteful
        and a risk-control signal."""
        if not self.session:
            return False
        resp = self.request("thing.m.user.info.get", "1.0", {},
                            session_require=True)
        return bool(resp.get("success"))

    def resolve_home(self, force: bool = False) -> Optional[int]:
        """Discover and cache homeId (gid) — the device list needs it."""
        if self.home_id is not None and not force:
            return self.home_id
        resp = self.list_homes()
        if not resp.get("success"):
            return None
        homes = resp.get("result") or []
        if isinstance(homes, list):
            for h in homes:
                if not isinstance(h, dict):
                    continue
                gid = h.get("gid") or h.get("groupId") or h.get("homeId")
                if gid is None:
                    continue
                self.home_id = int(gid)
                if h.get("admin") or len(homes) == 1:
                    break
        return self.home_id

    def device_detail(self, dev_id: str) -> Dict[str, Any]:
        """Device detail incl. current dps and localKey/mac/productId."""
        return self.request("thing.m.device.get", "1.0",
                            {"devId": dev_id}, session_require=True)

    def product_schema(self, home_id: Optional[int] = None) -> Any:
        """Product function schema: the numeric dpId <-> code-name map.

        `m.life.product.ext.prop.list v1.1 {"gid": N}` returns one entry per
        product bound to the home, each with standardConfig.functionSchemaList
        (writable DPs) and .statusSchemaList (read-only DPs). Each schema item
        carries relationDpIdMaps {code: dpId} — the only place the numeric
        dpId is tied to a code name for this account."""
        hid = home_id if home_id is not None else self.home_id
        if hid is None:
            return {"success": False, "error": "no homeId; call resolve_home()"}
        return self.request("m.life.product.ext.prop.list", "1.1",
                            {"gid": int(hid)}, session_require=True)

    def dp_map(self, home_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """Flatten product_schema() into [{productId, dpId, code, type, ...}]."""
        resp = self.product_schema(home_id)
        if not resp.get("success"):
            return []
        rows: List[Dict[str, Any]] = []
        items = resp["result"]
        for prod in (items if isinstance(items, list) else [items]):
            if not isinstance(prod, dict):
                continue
            pid = prod.get("id")
            sc = prod.get("standardConfig") or {}
            for key, ro in (("functionSchemaList", False),
                            ("statusSchemaList", True)):
                for f in sc.get(key) or []:
                    if not isinstance(f, dict):
                        continue
                    maps = f.get("relationDpIdMaps") or {}
                    dpids = [v for v in maps.values() if v is not None]
                    rows.append({
                        "productId": pid,
                        "dpId": dpids[0] if dpids else None,
                        "code": f.get("mainDpCode") or f.get("standardCode"),
                        "type": f.get("mainDpType") or f.get("standardType"),
                        "values": f.get("valueRange"),
                        "readonly": ro,
                    })
        return rows

    def device_spec(self, dev_id: str) -> Dict[str, Any]:
        """Per-device DP schema, from thing.m.device.get's embedded `schema`.

        Preference order: the device's own `schema` field (complete, carries
        dpId + code + Chinese name + mode + value range for every DP the
        device actually has), falling back to the home product schema."""
        detail = self.device_detail(dev_id)
        if not detail.get("success"):
            return detail
        result = detail.get("result") or {}
        raw = result.get("schema")
        rows: List[Dict[str, Any]] = []
        if isinstance(raw, str) and raw.strip():
            try:
                raw = json.loads(raw)
            except ValueError:
                raw = None
        for s in (raw or []):
            if not isinstance(s, dict):
                continue
            prop = s.get("property") or {}
            rows.append({
                "productId": result.get("productId"),
                "dpId": s.get("id"),
                "code": s.get("code"),
                "name": s.get("name"),
                "type": prop.get("type") or s.get("type"),
                "mode": s.get("mode"),
                "values": json.dumps(prop, ensure_ascii=False,
                                     separators=(",", ":")),
                "readonly": s.get("mode") == "ro",
            })
        if not rows:
            pid = result.get("productId")
            rows = [r for r in self.dp_map() if not pid or r["productId"] == pid]
        return {"success": bool(rows), "devId": dev_id,
                "productId": result.get("productId"),
                "localKey": result.get("localKey"), "schema": rows}




def save_session(path: str, client: TuyaCloudClient, region: str = None) -> None:
    """Persist everything needed to resume without a new login."""
    region = region or getattr(client, "region", "CN")
    prev = {}
    if os.path.exists(path):
        try:
            prev = json.load(open(path, encoding="utf-8"))
        except (OSError, ValueError):
            prev = {}
    rec = {"region": region, "session": client.session,
           "ecode": client.ecode, "deviceId": client.device_id,
           "homeId": client.home_id, "user": client.user,
           "loginTime": prev.get("loginTime") or int(time.time()),
           "lastUsed": int(time.time())}
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(rec, fh, ensure_ascii=False, indent=1)
    os.replace(tmp, path)


def load_session(path: str) -> Optional[Tuple[TuyaCloudClient, str]]:
    """Return (client, region) or None."""
    if not os.path.exists(path):
        return None
    d = json.load(open(path, encoding="utf-8"))
    region = d.get("region", "CN")
    c = TuyaCloudClient(region=region, device_id=d.get("deviceId"))
    c.session = d.get("session")
    c.ecode = d.get("ecode")
    c.home_id = d.get("homeId")
    c.user = d.get("user")
    return (c, region) if c.session else None


def ensure_session(state_path: str, secrets_path: str,
                   force_login: bool = False,
                   log=print) -> TuyaCloudClient:
    """THE entry point for credentials-based access.

    Reuses the persisted sid and only logs in when there is no session or the
    stored one is genuinely rejected. Callers must never call login_password()
    directly — repeated logins per process are a risk-control signal.
    """
    if not force_login:
        loaded = load_session(state_path)
        if loaded is not None:
            client, region = loaded
            if client.check_session():
                client.resolve_home()
                save_session(state_path, client, region)
                log(f"session reused (sid {client.session[:16]}...), no login")
                return client
            log("stored session rejected; logging in once")
    secrets = load_secrets(secrets_path)
    user, pwd = secrets.get("YOFS_USER"), secrets.get("YOFS_PASS")
    region = secrets.get("YOFS_REGION", "CN")
    cc = secrets.get("YOFS_CC", "86")
    if not user or not pwd:
        raise SystemExit(f"{secrets_path} must define YOFS_USER / YOFS_PASS")
    client = TuyaCloudClient(region)
    resp = client.login_password(cc, user, pwd)
    if not resp.get("success"):
        raise SystemExit(f"login failed: {json.dumps(resp, default=str)[:400]}")
    client.resolve_home()
    save_session(state_path, client, region)
    log(f"logged in once; session saved to {state_path}")
    return client


def flatten_devices(result: Any) -> List[Dict[str, Any]]:
    """Flatten the various device-list response shapes into device dicts."""
    out: List[Dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if ("devId" in node or "deviceId" in node or "id" in node) and                     ("localKey" in node or "name" in node or "productId" in node):
                out.append(node)
            else:
                for v in node.values():
                    walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(result)
    return out
