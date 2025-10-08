#!/usr/bin/env python3
import subprocess
import sys
import time
from typing import Tuple, Optional

APP_HOST = "192.168.20.2"
APP_USER = "app"
DMZ_HOST = "192.168.10.2"
DMZ_USER = "dmz"

SERVICES = {
    "blue": "chatapp@blue.service",
    "green": "chatapp@green.service",
}
PORTS = {"blue": 3001, "green": 3002}


def run_ssh(user: str, host: str, cmd: str) -> Tuple[int, str, str]:
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", f"{user}@{host}", cmd],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=30,
    )
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def sysd_props(service: str) -> Optional[dict]:
    cmd = (
        f"systemctl show {service} "
        "--property=ActiveState,SubState,ActiveEnterTimestampMonotonic --no-pager"
    )
    rc, out, err = run_ssh(APP_USER, APP_HOST, cmd)
    if rc != 0:
        print(f"ERR: systemctl show failed for {service}: {err}", file=sys.stderr)
        return None
    props = {}
    for line in out.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
    # Normalize monotonic timestamp to int
    try:
        props["ActiveEnterTimestampMonotonic"] = int(
            props.get("ActiveEnterTimestampMonotonic", "0")
        )
    except ValueError:
        props["ActiveEnterTimestampMonotonic"] = 0
    return props


def both_running(p_blue: dict, p_green: dict) -> bool:
    return (
        p_blue.get("ActiveState") == "active"
        and p_green.get("ActiveState") == "active"
    )


def pick_older(p_blue: dict, p_green: dict) -> str:
    # Smaller monotonic timestamp => started earlier => older
    tb = p_blue.get("ActiveEnterTimestampMonotonic", 0)
    tg = p_green.get("ActiveEnterTimestampMonotonic", 0)
    return "blue" if tb and (tb <= tg or not tg) else "green"


def http_ok(host: str, port: int, timeout_s: int = 3) -> bool:
    # Use curl over SSH on the app host to avoid local network assumptions
    cmd = (
        f"curl -s -S -o /dev/null -m {timeout_s} -w '%{{http_code}}' http://{host}:{port}/"
    )
    rc, out, err = run_ssh(APP_USER, APP_HOST, cmd)
    if rc != 0:
        return False
    try:
        code = int(out.strip() or "0")
    except ValueError:
        code = 0
    return 200 <= code < 400


def reload_nginx(app_port: int) -> bool:
    cmd = f"sudo /etc/nginx/templates/reload-nginx.sh {app_port}"
    rc, out, err = run_ssh(DMZ_USER, DMZ_HOST, cmd)
    if rc != 0:
        print(f"ERR: nginx reload failed: {err or out}", file=sys.stderr)
        return False
    return True


def stop_service(color: str) -> bool:
    svc = SERVICES[color]
    rc, out, err = run_ssh(APP_USER, APP_HOST, f"sudo systemctl stop {svc}")
    if rc != 0:
        print(f"ERR: failed to stop {svc}: {err or out}", file=sys.stderr)
        return False
    return True

def get_release_timestamp(color: str) -> Optional[str]:
    link = f"/srv/chatapp/{color}/current"
    # Resolve the symlink on the app host
    rc, out, err = run_ssh(APP_USER, APP_HOST, f"readlink -f {link} || true")
    if rc != 0 or not out:
        return None
    # Expect: /srv/chatapp/release/{timestamp}
    parts = out.strip().split("/")
    return parts[-1] if len(parts) >= 1 else None

def disable_service(color: str) -> bool:
    svc = SERVICES[color]
    rc, out, err = run_ssh(APP_USER, APP_HOST, f"sudo systemctl disable {svc}")
    if rc != 0:
        print(f"ERR: failed to disable {svc}: {err or out}", file=sys.stderr)
        return False
    return True

def main():
    p_blue = sysd_props(SERVICES["blue"])
    p_green = sysd_props(SERVICES["green"])
    if not p_blue or not p_green:
        sys.exit(2)

    if not both_running(p_blue, p_green):
        print("Two services must be running.")
        sys.exit(1)

    older = pick_older(p_blue, p_green)
    newer = "green" if older == "blue" else "blue"
    app_port = PORTS[older]

    print(f"Older color: {older}")
    print(f"Selected port: {app_port}")

    if not http_ok(APP_HOST, app_port):
        print(f"Health check failed for {older} on {APP_HOST}:{app_port}. Aborting.")
        sys.exit(3)

    if not reload_nginx(app_port):
        print("Failed to reload nginx on DMZ. Aborting.")
        sys.exit(4)

    time.sleep(5)

    # After deciding `older`, print the release timestamp
    ts = get_release_timestamp(older)
    if ts:
        print(f"Reverted to version {ts}")
    else:
        print(f"Could not resolve release version for {older}", file=sys.stderr)

    # Turn off the other service (assumed faulty or to be drained)
    if stop_service(newer):
        print(f"Stopped {newer} service.")
    else:
        sys.exit(5)

    if disable_service(newer):
        print(f"Disabled {newer} service.")
    else:
        sys.exit(6)


if __name__ == "__main__":
    main()
