"""mitmproxy addon — dump Tuya/YouFs API request+response pairs to files.

Usage:
    mitmdump -s tools/mitm_youfs.py --listen-host 0.0.0.0 --listen-port 8080 \
             -w work/mumu/flows.mitm

Writes:
    work/mumu/api_<n>_<api>.json  — one file per relevant flow:
        url, method, form fields (incl. sign/postData), response body
"""
import base64
import json
import os
import re
import urllib.parse
from datetime import datetime

OUT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                   "work", "mumu", "captures")
os.makedirs(OUT, exist_ok=True)
COUNTER = {"n": 0}
INTERESTING = ("gdyoufs.com", "tuyaeu.com", "tuyaus.com", "tuyacn.com",
               "tuyain.com", "iotbing.com")


def _is_interesting(host: str) -> bool:
    return any(h in host for h in INTERESTING)


def request(flow):
    if not _is_interesting(flow.request.pretty_host):
        return
    COUNTER["n"] += 1
    flow.metadata["youfs_n"] = COUNTER["n"]
    try:
        body = flow.request.get_text(strict=False) or ""
        form = dict(urllib.parse.parse_qsl(body)) if body else {}
        api = form.get("a", "?")
        rec = {
            "dir": "request",
            "time": datetime.now().isoformat(),
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "host": flow.request.pretty_host,
            "api": api,
            "form": form,
            "raw_body_len": len(body),
            "headers": dict(flow.request.headers),
        }
        name = f"{COUNTER['n']:03d}_req_{re.sub(r'[^A-Za-z0-9_.]', '_', api)}.json"
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
            json.dump(rec, fh, ensure_ascii=False, indent=1)
        print(f"[REQ {COUNTER['n']:03d}] {api} v={form.get('v')} "
              f"et={form.get('et')} sign={form.get('sign','')[:16]}... "
              f"postData={form.get('postData','')[:60]}")
    except Exception as exc:  # noqa: BLE001
        print(f"[REQ {COUNTER['n']:03d}] parse error: {exc}")


def response(flow):
    if not _is_interesting(flow.request.pretty_host):
        return
    n = flow.metadata.get("youfs_n", 0)
    try:
        text = flow.response.get_text(strict=False) or ""
        rec = {
            "dir": "response",
            "status": flow.response.status_code,
            "url": flow.request.pretty_url,
            "body": text[:20000],
            "headers": dict(flow.response.headers),
        }
        name = f"{n:03d}_resp.json"
        with open(os.path.join(OUT, name), "w", encoding="utf-8") as fh:
            json.dump(rec, fh, ensure_ascii=False, indent=1)
        print(f"[RESP {n:03d}] {flow.response.status_code} {text[:180]}")
    except Exception as exc:  # noqa: BLE001
        print(f"[RESP {n:03d}] parse error: {exc}")
