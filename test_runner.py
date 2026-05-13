#!/usr/bin/env python3
"""Integration test runner for TinyPage."""

import glob
import http.cookiejar
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import base64

BASE_AUTH = "Basic " + base64.b64encode(b"admin:testpass123#").decode()


def make_opener():
    cj = http.cookiejar.CookieJar()
    handler = urllib.request.HTTPCookieProcessor(cj)
    return urllib.request.build_opener(handler)


def main():
    opener = make_opener()

    def req(url, data=None):
        h = {"Authorization": BASE_AUTH}
        if data:
            data = data.encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        r = urllib.request.Request(url, data=data, headers=h, method="POST" if data else "GET")
        resp = opener.open(r, timeout=5)
        return resp.status, resp.read().decode("utf-8")

    # 1. Get CSRF
    _, html = req("http://127.0.0.1:8081/new")
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    csrf = m.group(1) if m else ""
    print("1. CSRF OK")

    # 2. Create article
    body = urllib.parse.urlencode({
        "csrf_token": csrf,
        "title": "现代CSS实验",
        "date": "2026-05-13 22:00",
        "tags": "CSS,WEB",
        "content": "这是**粗体**，这是*斜体*，这是`代码`。\n\n第二段。",
    })
    status, _ = req("http://127.0.0.1:8081/create", body)
    print(f"2. Create status={status}")
    time.sleep(1)

    # 3. Check files
    arts = glob.glob("pages/article/*.html")
    print(f"3. Articles: {[os.path.basename(a) for a in arts]}")

    # 4. Frontend
    status, idx = req("http://127.0.0.1:8080/")
    print(f"4a. Index title: {'现代CSS实验' in idx}")
    print(f"4b. Index tag: {'CSS' in idx}")

    if arts:
        art_name = urllib.parse.quote(os.path.basename(arts[0]))
        status, art = req(f"http://127.0.0.1:8080/article/{art_name}")
        print(f"4c. Article status={status}")
        if status == 200:
            print(f"4d. Article bold: {'<strong>' in art}")
            print(f"4e. Article tag: {'class=\"tag\"' in art}")
            print(f"4f. Dark mode: {'color-scheme' in art}")
            print(f"4g. View transition: {'view-transition' in art}")
            print(f"4h. Manifest: {'manifest.json' in art}")

    # 5. Preview
    prev_body = urllib.parse.urlencode({"csrf_token": csrf, "content": "Hello **world**"})
    status, prev = req("http://127.0.0.1:8081/preview", prev_body)
    print(f"5. Preview bold: {'<strong>' in prev}")

    # 6. RSS
    status, rss = req("http://127.0.0.1:8080/rss.xml")
    print(f"6. RSS status={status}, has title: {'现代CSS实验' in rss}")

    # 7. Sitemap
    status, sm = req("http://127.0.0.1:8080/sitemap.xml")
    print(f"7. Sitemap status={status}")

    # 8. Search index
    status, si = req("http://127.0.0.1:8080/search-index.json")
    print(f"8. Search index status={status}, has title: {'现代CSS实验' in si}")

    # 9. Search page
    status, sp = req("http://127.0.0.1:8080/search.html")
    print(f"9. Search page status={status}, has input: {'search-input' in sp}")

    # 10. Service Worker
    status, sw = req("http://127.0.0.1:8080/sw.js")
    print(f"10. SW status={status}, has cache: {'Cache API' in sw}")

    # 11. Delete
    if arts:
        fname = os.path.basename(arts[0])
        del_body = urllib.parse.urlencode({"csrf_token": csrf, "file": fname})
        status, _ = req("http://127.0.0.1:8081/delete", del_body)
        print(f"11. Delete status={status}")
        time.sleep(1)
        remaining = glob.glob("pages/article/*.html")
        print(f"11b. Remaining: {len(remaining)}")

    # 12. Regen
    regen_body = urllib.parse.urlencode({"csrf_token": csrf})
    status, _ = req("http://127.0.0.1:8081/regen", regen_body)
    print(f"12. Regen status={status}")

    print("\n=== All tests completed ===")


if __name__ == "__main__":
    main()
