import urllib.request
import urllib.parse
import http.cookiejar
import re
import time
import base64
import glob
import os

auth = "Basic " + base64.b64encode(b"admin:demo123#").decode()
cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))


def fetch(url, data=None):
    h = {"Authorization": auth}
    if data:
        data = data.encode()
        h["Content-Type"] = "application/x-www-form-urlencoded"
    r = urllib.request.Request(url, data=data, headers=h, method="POST" if data else "GET")
    resp = opener.open(r, timeout=5)
    return resp.status, resp.read().decode("utf-8")


def main():
    # Get CSRF
    _, html = fetch("http://127.0.0.1:8081/new")
    m = re.search(r'name="csrf_token" value="([^"]+)"', html)
    csrf = m.group(1) if m else ""

    # Create demo article
    body = urllib.parse.urlencode({
        "csrf_token": csrf,
        "title": "CSS Container Queries Demo",
        "date": "2026-05-13 22:00",
        "tags": "CSS,Frontend,Experiment",
        "content": "Container Queries are one of the most powerful new features in CSS.\n\nThey allow elements to respond to their **container's size** rather than the viewport size. This means we can create truly reusable components.\n\nWhy it matters:\n\nTraditional Media Queries only respond to viewport width. But in complex layouts, components may appear in sidebars, main content areas, or modals. Container queries let every component adapt **intelligently**.\n\nThis is a *revolutionary* change.\n\nCode example:\n`@container (min-width: 400px) { .card { grid-template-columns: 1fr 1fr; } }`\n\nMore resources: [MDN Docs](https://developer.mozilla.org/en-US/docs/Web/CSS/CSS_containment/Container_queries)",
    })
    status, _ = fetch("http://127.0.0.1:8081/create", body)
    print(f"Create article: HTTP {status}")
    time.sleep(1)

    # Determine article URL
    arts = glob.glob("pages/article/*.html")
    article_url = None
    if arts:
        fname = os.path.basename(arts[0])
        article_url = "http://127.0.0.1:8080/article/" + urllib.parse.quote(fname)

    snapshots = [
        ("frontend_index.html", "http://127.0.0.1:8080/"),
        ("frontend_article.html", article_url),
        ("frontend_search.html", "http://127.0.0.1:8080/search.html"),
        ("admin_dashboard.html", "http://127.0.0.1:8081/"),
        ("admin_new.html", "http://127.0.0.1:8081/new"),
    ]

    for name, url in snapshots:
        if not url:
            continue
        try:
            _, content = fetch(url)
            with open(f"snapshot_{name}", "w", encoding="utf-8") as f:
                f.write(content)
            print(f"Saved snapshot_{name} ({len(content)} bytes)")
        except Exception as e:
            print(f"Failed {name}: {e}")


if __name__ == "__main__":
    main()
