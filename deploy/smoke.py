#!/usr/bin/env python3
"""End-to-end check against a running セキュファイル便 instance.

Uploads a file in parts, interrupts and resumes it, then downloads and
compares hashes. Written in Python rather than shell because the filename
check has to compare UTF-8 exactly, which a shell on a non-UTF-8 console
cannot do reliably.

Usage: python3 smoke.py [base-url] [--size-mb N]
"""

import argparse
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request

FILENAME = "大容量テスト_2026年度.bin"


def _lc(h):
    return {k.lower(): v for k, v in h.items()}


def request(method, url, body=None, headers=None, raw=False):
    req = urllib.request.Request(url, data=body, method=method)
    # A browser-like UA so Cloudflare's Browser Integrity Check does not flag
    # this test client (real users upload from a browser and pass anyway).
    req.add_header("User-Agent",
                   "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/140.0 Safari/537.36")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req) as res:
            payload = res.read()
            return res.status, _lc(res.headers), payload if raw else json.loads(payload or b"{}")
    except urllib.error.HTTPError as err:
        payload = err.read()
        try:
            return err.code, _lc(err.headers), json.loads(payload or b"{}")
        except json.JSONDecodeError:
            return err.code, _lc(err.headers), {"error": payload[:200].decode("utf-8", "replace")}


def json_request(method, url, obj=None, headers=None):
    body = json.dumps(obj).encode() if obj is not None else None
    head = {"Content-Type": "application/json", **(headers or {})}
    return request(method, url, body, head)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("base", nargs="?", default="http://127.0.0.1:8080")
    parser.add_argument("--size-mb", type=int, default=64)
    args = parser.parse_args()
    base = args.base.rstrip("/")

    print(f"target: {base}")
    data = os.urandom(args.size_mb * 1024 * 1024)
    want = hashlib.sha256(data).hexdigest()
    print(f"payload: {len(data)} bytes, sha256 {want}")

    status, _, start = json_request("POST", f"{base}/api/uploads", {
        "files": [{"name": FILENAME, "size": len(data)}],
        "days": 1,
        "maxDownloads": 5,
    })
    if status != 201:
        sys.exit(f"FAIL: start upload returned {status}: {start}")

    key, sid = start["key"], start["sessionId"]
    token, password = start["token"], start["password"]
    part_size, file_id = start["partSize"], start["files"][0]["id"]
    print(f"share {key}, part size {part_size}")

    def send(offset, chunk):
        return request("PATCH", f"{base}/api/uploads/{sid}/files/{file_id}", chunk, {
            "Authorization": f"Bearer {token}",
            "Upload-Offset": str(offset),
            "Content-Type": "application/octet-stream",
        })

    # Send a few parts, then stop as if the connection had dropped.
    offset = 0
    for _ in range(min(3, len(data) // part_size)):
        status, _, body = send(offset, data[offset:offset + part_size])
        if status != 200:
            sys.exit(f"FAIL: part at {offset} returned {status}: {body}")
        offset += part_size
    print(f"sent {offset} bytes, simulating an interruption")

    status, _, state = request("GET", f"{base}/api/uploads/{sid}",
                               headers={"Authorization": f"Bearer {token}"})
    received = state["files"][0]["received"]
    if received != offset:
        sys.exit(f"FAIL: server holds {received} bytes, expected {offset}")
    print(f"server reports {received} bytes stored — resume point confirmed")

    # A replayed part must be refused with the offset to continue from, not
    # silently appended.
    status, headers, body = send(0, data[:part_size])
    if status != 409:
        sys.exit(f"FAIL: replayed part returned {status}, expected 409")
    if headers.get("upload-offset") != str(offset):
        sys.exit(f"FAIL: 409 reported offset {headers.get('Upload-Offset')}, expected {offset}")
    print("replayed part correctly refused with 409 and the expected offset")

    began = time.monotonic()
    while offset < len(data):
        chunk = data[offset:offset + part_size]
        status, _, body = send(offset, chunk)
        if status != 200:
            sys.exit(f"FAIL: part at {offset} returned {status}: {body}")
        offset += len(chunk)
    elapsed = time.monotonic() - began
    print(f"resumed and finished: {len(data) / max(elapsed, 1e-9) / 1e6:.1f} MB/s")

    status, _, body = json_request("POST", f"{base}/api/uploads/{sid}/finish", {},
                                   {"Authorization": f"Bearer {token}"})
    if status != 200:
        sys.exit(f"FAIL: finish returned {status}: {body}")

    status, _, wrong = json_request("POST", f"{base}/api/drops/{key}/unlock",
                                    {"password": "this-is-not-the-password"})
    if status != 401:
        sys.exit(f"FAIL: wrong password returned {status}, expected 401")
    print("wrong password rejected")

    status, _, unlocked = json_request("POST", f"{base}/api/drops/{key}/unlock",
                                       {"password": password})
    if status != 200:
        sys.exit(f"FAIL: unlock returned {status}: {unlocked}")

    got_name = unlocked["files"][0]["name"]
    if got_name != FILENAME:
        sys.exit(f"FAIL: filename round trip: got {got_name!r}, want {FILENAME!r}")
    print(f"filename decrypted correctly: {got_name}")

    session = unlocked["token"]
    status, _, ticket = json_request("POST", f"{base}/api/session/tickets",
                                     {"fileId": unlocked["files"][0]["id"]},
                                     {"X-Session-Token": session})
    if status != 200:
        sys.exit(f"FAIL: ticket returned {status}: {ticket}")

    began = time.monotonic()
    status, headers, payload = request("GET", base + ticket["url"], raw=True)
    elapsed = time.monotonic() - began
    if status != 200:
        sys.exit(f"FAIL: download returned {status}")
    print(f"downloaded {len(payload)} bytes at {len(payload) / max(elapsed, 1e-9) / 1e6:.1f} MB/s")

    got = hashlib.sha256(payload).hexdigest()
    if got != want or len(payload) != len(data):
        sys.exit(f"FAIL: content mismatch — got sha256 {got}")

    # A ranged read, which is what a resuming download issues.
    mid = len(data) // 2
    status, headers, ranged = request("GET", base + ticket["url"], raw=True,
                                      headers={"Range": f"bytes={mid}-{mid + 999}"})
    if status != 206:
        sys.exit(f"FAIL: ranged request returned {status}, expected 206")
    if ranged != data[mid:mid + 1000]:
        sys.exit("FAIL: ranged request returned the wrong bytes")
    print(f"range request served correctly ({headers.get('content-range')})")

    print(f"\nPASS — {args.size_mb} MiB round-tripped byte-for-byte "
          f"through an interrupted, resumed upload")


if __name__ == "__main__":
    main()
