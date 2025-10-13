#!/usr/bin/env python3
import json, os, sys, ssl, urllib.request, urllib.error
from datetime import datetime, timezone
from pathlib import Path

def iso_utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def env(name, default=None, required=False):
    v = os.getenv(name, default)
    if required and (v is None or v == ""):
        print(f"Missing required env: {name}", file=sys.stderr)
        sys.exit(2)
    return v

def build_ssl_context():
    cafile = os.getenv("ES_CA_CERT")
    if cafile and os.path.exists(cafile):
        ctx = ssl.create_default_context(cafile=cafile)
    else:
        ctx = ssl.create_default_context()
    if os.getenv("ES_SKIP_TLS_VERIFY","").lower() in ("1","true","yes"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx

def get_version_from_package_json():

    # Route 1: GitLab CI environment
    ci_dir = os.getenv("CI_PROJECT_DIR")
    if ci_dir and Path(ci_dir, "package.json").exists():
        pkg_path = Path(ci_dir, "package.json")

    # Fallback: check if current working directory is GitLab build folder
    elif "/builds/" in os.getcwd() and Path(os.getcwd(), "package.json").exists():
        pkg_path = Path(os.getcwd(), "package.json")

    # Route 2: Local run (package.json is sibling to this script)
    else:
        pkg_path = Path(__file__).resolve().parent / "package.json"

    if pkg_path.exists():
        try:
            with open(pkg_path, encoding="utf-8") as f:
                return json.load(f).get("version")
        except Exception as e:
            print(f"Warning: could not read package.json ({e})", file=sys.stderr)
    else:
        print(f"Warning: package.json not found at {pkg_path}", file=sys.stderr)
    return None

def main():
    es_url   = env("ES_URL", required=True).rstrip("/")
    index    = env("ES_INDEX", "app-releases")
    commit   = env("COMMIT", required=True)
    started  = env("STARTED_AT", required=True)
    envname  = env("ENVIRONMENT", "Production")
    version = get_version_from_package_json()
    if not version:
        print("Error: RELEASE_VERSION not set and no version in package.json", file=sys.stderr)
        sys.exit(2)

    finishTime= env("FINISHED_AT", iso_utc_now())
    payload = {
        "@timestamp": finishTime,
        "version": version,
        "commit": commit,
        "started_at": started,
        "finished_at": finishTime,
        "env": envname
    }
    data = json.dumps(payload).encode("utf-8")

    url = f"{es_url}/{index}/_doc"
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")

    # API key authentication
    api_key = env("ES_API_KEY", required=True)
    req.add_header("Authorization", f"ApiKey {api_key}")

    ctx = build_ssl_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=20) as resp:
            print(resp.read().decode("utf-8", "replace"))
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code}: {e.read().decode('utf-8','replace')}", file=sys.stderr)
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"URL error: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
