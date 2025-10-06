#!/usr/bin/env python3
import sys, os, subprocess, time, urllib.request

RELEASE_ROOT = "/srv/chatapp/release"
COLOR_ROOT   = "/srv/chatapp"              # expects /srv/chatapp/<color>/current
PORTS = {"blue": 3001, "green": 3002}
UNIT  = "chatapp@{}.service"

def sh(cmd):
    return subprocess.run(cmd, shell=True, check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

def is_active(color):
    r = sh(f"sudo systemctl is-active {UNIT.format(color)}")
    return r.stdout.strip() == "active"

def active_mono(color):
    r = sh(f"sudo systemctl show {UNIT.format(color)} -p ActiveEnterTimestampMonotonic --value")
    val = r.stdout.strip()
    try:
        return int(val)
    except ValueError:
        return 0

def ensure_paths(color, target):
    os.makedirs(os.path.join(COLOR_ROOT, color), exist_ok=True)
    # atomic swap of symlink
    sh(f"ln -sfn {target} {os.path.join(COLOR_ROOT, color, 'current')}")

def start_enable(color):
    sh(f"sudo systemctl enable {UNIT.format(color)}")
    r = sh(f"sudo systemctl start {UNIT.format(color)}")
    return r.returncode == 0

def stop_unit(color):
    sh(f"sudo systemctl stop {UNIT.format(color)}")

def probe(port, attempts=5, delay=2):
    url = f"http://127.0.0.1:{port}/"
    for _ in range(attempts):
        try:
            with urllib.request.urlopen(url, timeout=2) as resp:
                if 200 <= resp.status < 500:
                    return True
        except Exception:
            pass
        time.sleep(delay)
    return False

def pick_color():
    blue_active  = is_active("blue")
    green_active = is_active("green")
    if not blue_active:
        return "blue", False
    if not green_active:
        return "green", False
    # both active -> replace older one
    b_m = active_mono("blue")
    g_m = active_mono("green")
    return ("blue" if b_m <= g_m else "green"), True

def main():
    if len(sys.argv) != 2:
        print("usage: deploy.py <timestamp>", file=sys.stderr)
        sys.exit(2)
    ts = sys.argv[1]
    new_release = os.path.join(RELEASE_ROOT, ts)
    if not os.path.isdir(new_release):
        print(f"release not found: {new_release}", file=sys.stderr)
        sys.exit(3)

    color, replace_running = pick_color()
    if replace_running:
        stop_unit(color)

    ensure_paths(color, new_release)

    if not start_enable(color):
        print(f"failed to start {UNIT.format(color)}", file=sys.stderr)
        sys.exit(4)

    if not probe(PORTS[color]):
        print(f"health check failed on {color}:{PORTS[color]}", file=sys.stderr)
        sys.exit(5)

    print(color)  # required output

if __name__ == "__main__":
    main()
