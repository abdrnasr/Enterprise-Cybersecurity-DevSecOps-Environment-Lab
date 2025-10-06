#!/usr/bin/env python3
import sys
import os
import ssl
import http.client
from urllib.parse import urlparse

def run_seeding(base: str, secret: str):
    # Ensure scheme is included
    if "://" not in base:
        base = "http://" + base
    url = base.rstrip("/") + "/api/seeding"

    # Print endpoint being hit
    print(f"Hitting endpoint: {url}")

    parsed = urlparse(url)
    host, port = parsed.hostname, parsed.port
    scheme, path = parsed.scheme, parsed.path

    if not port:
        port = 443 if scheme == "https" else 80

    context = None
    if scheme == "https":
        print(os.getenv("SEEDING_CA_CERT"))
        ca_path = os.getenv("SEEDING_CA_CERT")
        if ca_path:
            context = ssl.create_default_context(cafile=ca_path)
        else:
            context = ssl.create_default_context()

    try:
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port, context=context, timeout=5)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=5)

        headers = {"x-seeding-secret": secret}
        conn.request("GET", path, headers=headers)
        response = conn.getresponse()

        body = response.read().decode(errors="ignore")

        if response.status == 200:
            print("Seeding successful!")
            print("Response:", body)
            sys.exit(0)
        else:
            print(f"Seeding failed with status {response.status}")
            print("Response:", body)
            sys.exit(response.status)
    except Exception as e:
        print("Seeding failed:", e)
        sys.exit(1)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: seeding.py <host:port | full_url>")
        print("Examples:")
        print("  seeding.py 192.168.33.6:3000")
        print("  seeding.py http://192.168.33.6:8443")
        sys.exit(1)

    base_arg = sys.argv[1]
    secret = os.getenv("SEEDING_SECRET")

    if not secret:
        print("No SEEDING_SECRET passed")
        sys.exit(2)

    run_seeding(base_arg, secret)