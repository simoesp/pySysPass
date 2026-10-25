"""Verify effective nginx headers on SPA routes and a real built asset."""

import argparse
import re
import time
from urllib.error import URLError
from urllib.request import urlopen


def check(base_url: str) -> None:
    base_url = base_url.rstrip("/")
    # nginx may accept and then reset connections while the container starts.
    for attempt in range(60):
        try:
            with urlopen(base_url + "/", timeout=2) as response:
                html = response.read().decode()
            break
        except (URLError, ConnectionError):
            if attempt == 59:
                raise
            time.sleep(0.5)
    asset = re.search(r'(?:src|href)="(/assets/[^"<>]+)"', html)
    assert asset is not None, "Built application asset not found"
    for path in ("/", "/index.html", "/login", asset.group(1)):
        with urlopen(base_url + path, timeout=5) as response:
            headers = response.headers
            assert response.status == 200, path
            assert "frame-ancestors 'none'" in headers.get("Content-Security-Policy", ""), path
            assert headers.get("X-Frame-Options") == "DENY", path
            assert headers.get("X-Content-Type-Options") == "nosniff", path
            assert headers.get("Referrer-Policy") == "strict-origin-when-cross-origin", path
            assert headers.get("Permissions-Policy"), path
            expected = "public, max-age=31536000, immutable" if path.startswith("/assets/") else "no-store"
            assert headers.get("Cache-Control") == expected, path
        print(f"Headers verified: {path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("url", help="URL of the built frontend container")
    check(parser.parse_args().url)
