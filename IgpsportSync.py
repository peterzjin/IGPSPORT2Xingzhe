"""
Sync iGPSPORT rides to Xingzhe (imxingzhe.com).

Replaces the old my.igpsport.com flow (dead: 504 + TLS interception) with the
current app.igpsport.cn / prod.zh.igpsport.com backend, which requires a
per-request signature produced by iGPSPORT's own edge_core WASM.

Credentials come from env vars USERNAME / PASSWORD (shared by both sites).
Run options are CLI flags: --limit N, --dry_run.
"""
import argparse
import base64
import hashlib
import os
import re
import time
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

import requests
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from wasmtime import Store, Module, Instance, Func, FuncType, ValType

IGP_API = "https://prod.zh.igpsport.com"
IGP_APP = "https://app.igpsport.cn"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36")
TZ = ZoneInfo("Asia/Shanghai")
DEDUP_WINDOW_MS = 100_000  # ±100s, same as the original script


# --------------------------------------------------------------------------- #
# Signing layer: load iGPSPORT's edge_core WASM (fetched at runtime) and
# reproduce generate_signature(method, path, ts, nonce, body).
# --------------------------------------------------------------------------- #
class IgpSigner:
    def __init__(self, secret_b64):
        wasm = self._download_wasm()
        self.store = Store()
        module = Module(self.store.engine, wasm)
        self.exports = None

        def init_externref_table():
            tbl = self.exports["__wbindgen_externrefs"]
            base = tbl.grow(self.store, 4, None)
            for i, v in enumerate([None, None, None, None]):
                tbl.set(self.store, base + i, v)

        by_name = {
            "__wbindgen_cast_2241b6af4c4b2941":
                Func(self.store, FuncType([ValType.i32(), ValType.i32()],
                                          [ValType.externref()]), lambda t, a: None),
            "__wbindgen_init_externref_table":
                Func(self.store, FuncType([], []), init_externref_table),
        }
        ordered = [by_name[imp.name] for imp in module.imports]
        self.instance = Instance(self.store, module, ordered)
        self.exports = self.instance.exports(self.store)
        self.mem = self.exports["memory"]
        self.exports["__wbindgen_start"](self.store)
        self._init_key(self._decode_secret(secret_b64))

    @staticmethod
    def _download_wasm():
        """index.html -> entry js -> current .wasm (no hardcoded hash)."""
        idx = requests.get(IGP_APP + "/", headers={"User-Agent": UA}, timeout=30).text
        entry = re.search(r"/assets/js/[A-Za-z0-9_-]+\.js", idx)
        if not entry:
            raise RuntimeError("找不到入口 JS，iGPSPORT 页面结构可能已变更")
        js = requests.get(IGP_APP + entry.group(0), headers={"User-Agent": UA}, timeout=30).text
        wasm = re.search(r"/assets/[A-Za-z0-9_-]*wasm[A-Za-z0-9_-]*\.wasm", js)
        if not wasm:
            raise RuntimeError("找不到签名 WASM 地址，iGPSPORT 前端可能已升级")
        return requests.get(IGP_APP + wasm.group(0), headers={"User-Agent": UA}, timeout=30).content

    @staticmethod
    def _decode_secret(e):
        t = re.sub(r"\s+", "", e)
        a = t.replace("-", "+").replace("_", "/")
        return base64.b64decode(a + "=" * ((4 - len(t) % 4) % 4))

    # -- wasm memory helpers (mirror the site's wasm-bindgen glue) --
    def _write(self, data):
        ptr = self.exports["__wbindgen_malloc"](self.store, len(data), 1)
        buf = self.mem.get_buffer_ptr(self.store)
        for i, b in enumerate(data):
            buf[ptr + i] = b
        self._len = len(data)
        return ptr

    def _init_key(self, secret):
        ptr = self._write(secret)
        r = self.exports["init_session_key"](self.store, ptr, self._len)
        if r[2]:
            raise RuntimeError("init_session_key failed")

    def _signature(self, method, path, ts, nonce, body):
        f = self._write(method.encode()); m = self._len
        p = self._write(path.encode()); pl = self._len
        g = self._write(ts.encode()); gl = self._len
        e = self._write(nonce.encode()); el = self._len
        c = self._write(body); cl = self._len
        w = self.exports["generate_signature"](self.store, f, m, p, pl, g, gl, e, el, c, cl)
        if w[3]:
            raise RuntimeError("generate_signature error")
        out = bytes(self.mem.get_buffer_ptr(self.store)[w[0]:w[0] + w[1]]).decode()
        self.exports["__wbindgen_free"](self.store, w[0], w[1], 1)
        return out

    @staticmethod
    def _canonical_query(params):
        parts = []
        for k, v in params.items():
            if v is None:
                continue
            from urllib.parse import quote
            r = quote(str(v), safe="")
            r = (r.replace("%20", "+").replace("'", "%27").replace("%2C", ",")
                  .replace("%3A", ":").replace("%24", "$"))
            parts.append(f"{k}={r}")
        return "&".join(parts)

    def build_path(self, url, params=None):
        a = url if url.startswith("/") else "/" + url
        if params:
            q = self._canonical_query(params)
            if q:
                a += "?" + q
        a = re.sub(r"/{2,}", "/", a)
        return a if "/service" in a else "/service" + a

    def headers(self, method, path, body=b""):
        """Return the 4 signature headers. nonce MUST be a fresh uuid4 (anti-replay)."""
        ts = str(int(time.time()))
        nonce = str(uuid.uuid4())
        sig = self._signature(method, path, ts, nonce, body)
        return {"x-access-key": "AKIDWebClient", "x-timestamp": ts,
                "x-nonce": nonce, "x-signature": sig, "x-platform": "web"}


# --------------------------------------------------------------------------- #
# iGPSPORT client
# --------------------------------------------------------------------------- #
class IgpClient:
    def __init__(self):
        self.session = requests.session()
        secret = self._raw_get("/service/edge-core/api/public/key")["data"]["secret_key"]
        self.signer = IgpSigner(secret)
        self.token = None

    def _base_headers(self):
        h = {"User-Agent": UA, "Origin": IGP_APP, "Referer": IGP_APP + "/",
             "qiwu-app-version": "8.07.08", "timezone": "Asia/Shanghai",
             "Accept": "application/json, text/plain, */*"}
        if self.token:
            h["Authorization"] = "Bearer " + self.token
        return h

    def _raw_get(self, path):
        """Unsigned GET (only for the public key endpoint)."""
        r = self.session.get(IGP_API + path, headers={"User-Agent": UA, "x-platform": "web"},
                             timeout=30)
        return r.json()

    def _get(self, url, params=None, retries=3):
        path = self.signer.build_path(url, params)
        for attempt in range(retries):
            h = {**self._base_headers(), **self.signer.headers("GET", path)}
            r = self.session.get(IGP_API + path, headers=h, timeout=30)
            if r.status_code == 200:
                return r.json()
            time.sleep(1)  # 500 is usually a transient/anti-replay hiccup; retry with new nonce
        r.raise_for_status()

    def _post(self, url, body_obj, retries=3):
        import json as _json
        path = self.signer.build_path(url, None)
        body = _json.dumps(body_obj, separators=(",", ":")).encode()
        for attempt in range(retries):
            h = {**self._base_headers(), "Content-Type": "application/json",
                 **self.signer.headers("POST", path, body)}
            r = self.session.post(IGP_API + path, data=body, headers=h, timeout=30)
            if r.status_code == 200:
                return r.json()
            time.sleep(1)  # transient/anti-replay hiccup; retry with a fresh nonce
        r.raise_for_status()

    def login(self, username, password):
        res = self._post("/service/auth/account/login",
                         {"appId": "igpsport-web", "username": username, "password": password})
        self.token = res["data"]["access_token"]
        return self.token

    def iter_activities(self, limit):
        """Yield up to `limit` activities, newest first."""
        got, page = 0, 1
        while got < limit:
            data = self._get("/service/web-gateway/web-analyze/activity/queryMyActivity",
                             {"pageNo": page, "pageSize": 20, "reqType": 0,
                              "sort": 1, "sortType": 1})["data"]
            rows = data.get("rows", [])
            if not rows:
                break
            for row in rows:
                yield row
                got += 1
                if got >= limit:
                    return
            if page >= data.get("totalPage", page):
                break
            page += 1

    def start_time(self, ride_id):
        """Precise start time 'YYYY-MM-DD HH:MM:SS' from the detail endpoint."""
        d = self._get(f"/service/web-gateway/web-analyze/activity/queryActivityDetail/{ride_id}")
        return d["data"]["startTime"]

    def download_fit(self, ride_id):
        url = self._get(f"/service/web-gateway/web-analyze/activity/getDownloadUrl/{ride_id}")["data"]
        return self.session.get(url, headers={"User-Agent": UA}, timeout=60).content


# --------------------------------------------------------------------------- #
# Xingzhe client (behavior kept identical to the original script)
# --------------------------------------------------------------------------- #
XINGZHE_PUBKEY = (
    "-----BEGIN PUBLIC KEY-----\n"
    "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDmuQkBbijudDAJgfffDeeIButq\n"
    "WHZvUwcRuvWdg89393FSdz3IJUHc0rgI/S3WuU8N0VePJLmVAZtCOK4qe4FY/eKm\n"
    "WpJmn7JfXB4HTMWjPVoyRZmSYjW4L8GrWmh51Qj7DwpTADadF3aq04o+s1b8LXJa\n"
    "8r6+TIqqL5WUHtRqmQIDAQAB\n-----END PUBLIC KEY-----\n"
)


class XingzheClient:
    def __init__(self):
        self.session = requests.session()
        self.session.headers.update({"User-Agent": UA, "Accept-Encoding": "gzip, deflate"})

    @staticmethod
    def _encrypt(password):
        cipher = PKCS1_v1_5.new(RSA.importKey(XINGZHE_PUBKEY))
        return base64.b64encode(cipher.encrypt(password.encode())).decode()

    def login(self, username, password):
        res = self.session.post("https://www.imxingzhe.com/api/v1/user/login/",
                                json={"account": username, "password": self._encrypt(password)},
                                timeout=30)
        res.raise_for_status()
        return res.json()["data"]["username"]

    def recent_start_times(self, count=10):
        """start_time (ms) of the latest synced cycling workouts, for dedup."""
        url = ("https://www.imxingzhe.com/api/v1/pgworkout/"
               f"?offset=0&limit={count}&sport=3&year=&month=")
        return [w["start_time"] for w in self.session.get(url, timeout=30).json()["data"]["data"]]

    def upload_fit(self, name, filename, content):
        return self.session.post("https://www.imxingzhe.com/api/v1/fit/upload/", files={
            "file_source": (None, "undefined", None),
            "fit_filename": (None, filename, None),
            "md5": (None, hashlib.md5(content).hexdigest(), None),
            "name": (None, name, None),
            "sport": (None, 3, None),
            "fit_file": (filename, content, "application/octet-stream"),
        })


# --------------------------------------------------------------------------- #
# Main flow
# --------------------------------------------------------------------------- #
def to_ms(start_time_str):
    dt = datetime.strptime(start_time_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=TZ)
    return int(dt.timestamp()) * 1000


def sync(username, password, limit=10, dry_run=False):
    if not username or not password:
        raise SystemExit("请设置环境变量 USERNAME 和 PASSWORD")
    igp = IgpClient()
    igp.login(username, password)
    print("iGPSPORT 登录成功")

    xz = XingzheClient()
    print("行者用户名: %s" % xz.login(username, password))
    # Dedup against the latest 10 synced records: within that window, match each
    # activity exactly (so gaps from past upload failures get re-synced); older
    # than the window's oldest record is assumed already synced.
    existing = xz.recent_start_times()
    cutoff = min(existing) if existing else None

    for act in igp.iter_activities(limit):
        ride_id = act["rideId"]
        start = igp.start_time(ride_id)
        ms = to_ms(start)
        if cutoff is not None and ms < cutoff:
            print("跳过(超出比对范围,视为已同步): %s %s" % (ride_id, start))
            continue
        if any(abs(ms - e) < DEDUP_WINDOW_MS for e in existing):
            print("跳过(已同步): %s %s" % (ride_id, start))
            continue
        name, filename = "IGPSPORT-" + start, start + ".fit"
        if dry_run:
            print("[dry-run] 待同步(未下载/未上传): %s" % name)
            continue
        fit = igp.download_fit(ride_id)
        r = xz.upload_fit(name, filename, fit)
        print("上传 %s: %s" % (name, r.text))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Sync iGPSPORT rides to Xingzhe.")
    parser.add_argument("--limit", type=int, default=10,
                        help="number of recent activities to check (default 10)")
    parser.add_argument("--dry_run", action="store_true",
                        help="list what would sync without downloading or uploading")
    args = parser.parse_args()
    sync(os.getenv("USERNAME"), os.getenv("PASSWORD"),
         limit=args.limit, dry_run=args.dry_run)
