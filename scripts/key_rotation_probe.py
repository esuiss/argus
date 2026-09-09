"""`key-rotation-test.sh` için token basma ve kullanma yardımcısı."""

import base64
import hashlib
import json
import os
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ["ARGUS_ROTATION_BASE"]
STORE = os.environ["ARGUS_ROTATION_TOKENS"]
CLIENT = "demo-client"
REDIRECT = "http://127.0.0.1/callback"

def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_a, **_k):
        return None

opener = urllib.request.build_opener(NoRedirect)

def mint(_ignored):
    verifier = b64(secrets.token_bytes(32))
    challenge = b64(hashlib.sha256(verifier.encode()).digest())
    query = urllib.parse.urlencode(
        {
            "response_type": "code",
            "client_id": CLIENT,
            "redirect_uri": REDIRECT,
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "openid",
        }
    )
    try:
        opener.open(urllib.request.Request(f"{BASE}/authorize?{query}"))
        raise SystemExit("authorize did not redirect")
    except urllib.error.HTTPError as err:
        location = err.headers["Location"]
    code = urllib.parse.parse_qs(urllib.parse.urlparse(location).query)["code"][0]

    body = urllib.parse.urlencode(
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT,
            "code_verifier": verifier,
            "client_id": CLIENT,
        }
    ).encode()
    response = urllib.request.urlopen(urllib.request.Request(f"{BASE}/token", data=body))
    return json.load(response)["access_token"]

def use(token):
    request = urllib.request.Request(
        f"{BASE}/userinfo", headers={"Authorization": "Bearer " + token}
    )
    try:
        return urllib.request.urlopen(request).status
    except urllib.error.HTTPError as err:
        return err.code
    except OSError:
        return 0

def main():
    mode, count_or_status = sys.argv[1], int(sys.argv[2])

    if mode == "mint":
        with ThreadPoolExecutor(16) as pool:
            tokens = list(pool.map(mint, range(count_or_status)))
        with open(STORE, "w", encoding="utf-8") as handle:
            json.dump(tokens, handle)
        kids = {
            json.loads(base64.urlsafe_b64decode(t.split(".")[0] + "=="))["kid"]
            for t in tokens
        }
        print(f"basilan: {len(tokens)} | imzalayan kid: {sorted(kids)}")
        return

    with open(STORE, encoding="utf-8") as handle:
        tokens = json.load(handle)
    with ThreadPoolExecutor(16) as pool:
        codes = Counter(pool.map(use, tokens))

    print(f"beklenen {count_or_status}: {dict(codes)}")
    if set(codes) != {count_or_status}:
        raise SystemExit(f"FAIL: expected every request to return {count_or_status}")

main()
