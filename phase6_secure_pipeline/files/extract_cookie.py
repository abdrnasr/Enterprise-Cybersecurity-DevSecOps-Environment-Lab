# extract_cookie.py
# pip install playwright
# python -m playwright install
#
# ENV:
#   KEYCLOAK_USER, KEYCLOAK_PASS  -> credentials
#   START_URL  (default: http://192.168.20.2:3005/api/auth/signin)
#   APP_HOST   (default: 192.168.20.2)   # host to keep cookies for the output header
#
# OUTPUT:
#   cookies.json        # all cookies from the context
#   cookies_header.txt  # Cookie header only for APP_HOST

import os, sys, json, time
from pathlib import Path
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright, TimeoutError as PTimeout # type: ignore

APP_HOST  = os.getenv("APP_HOST", "192.168.20.2")
START_URL = os.getenv("START_URL", f"http://{APP_HOST}:3005/api/auth/signin")
USER = os.getenv("KEYCLOAK_USER")
PASS = os.getenv("KEYCLOAK_PASS")

if not USER or not PASS:
    print("Set KEYCLOAK_USER and KEYCLOAK_PASS.", file=sys.stderr)
    sys.exit(2)

print(f"Using app host: {APP_HOST}, start URL: {START_URL}, credentials: {USER}")

USERNAME_SELECTOR = "input#username, input[name='username']"
PASSWORD_SELECTOR = "input#password, input[name='password']"
LOGIN_BUTTON_SELECTOR = "button#kc-login, input#kc-login, button[type=submit]"
KC_URL_HINTS = ("realms/", "openid-connect", "/protocol/")  # helps detect Keycloak pages

def cookies_to_header(cookies):
    pairs = [f"{c['name']}={c['value']}" for c in cookies]
    return "; ".join(pairs)

def is_keycloak_url(u: str) -> bool:
    t = u.lower()
    return any(h in t for h in KC_URL_HINTS)

def run():
    with sync_playwright() as p:
        # allow self-signed TLS if any https redirects appear
        browser = p.chromium.launch(headless=True, args=["--ignore-certificate-errors"])
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        # 1) Go to NextAuth signin page and click "Sign in with Keycloak"
        page.goto(START_URL, timeout=45000)

        # Try role-based first, then text, then a link
        clicked = False
        for attempt in range(3):
            try:
                page.get_by_role("button", name="Sign in with Keycloak", exact=True).click(timeout=3000)
                clicked = True
                break
            except Exception:
                try:
                    page.get_by_text("Sign in with Keycloak", exact=False).click(timeout=3000)
                    clicked = True
                    break
                except Exception:
                    try:
                        page.click("a:has-text('Sign in with Keycloak')", timeout=3000)
                        clicked = True
                        break
                    except Exception:
                        time.sleep(0.5)
        if not clicked:
            print("Could not find the 'Sign in with Keycloak' control.", file=sys.stderr)
            browser.close()
            sys.exit(3)

        # 2) Wait for navigation to Keycloak login page
        try:
            page.wait_for_load_state("domcontentloaded", timeout=15000)
        except PTimeout:
            pass

        # Some setups open a popup. Ensure we stay on the active page.
        # If a popup happens, switch to it.
        for _ in range(5):
            if is_keycloak_url(page.url):
                break
            # check for newly opened pages
            if len(context.pages) > 1:
                for pg in context.pages:
                    if is_keycloak_url(pg.url):
                        page = pg
                        break
            time.sleep(0.5)

        # 3) Fill Keycloak credentials and submit
        try:
            page.wait_for_selector(USERNAME_SELECTOR, timeout=30000)
        except PTimeout:
            print("Keycloak username field not found.", file=sys.stderr)
            browser.close()
            sys.exit(4)

        page.fill(USERNAME_SELECTOR, USER)
        page.fill(PASSWORD_SELECTOR, PASS)
        try:
            page.click(LOGIN_BUTTON_SELECTOR, timeout=5000)
        except PTimeout:
            page.keyboard.press("Enter")

        # 4) Wait until redirected back to the app origin (NextAuth callback complete)
        app_origin = f"{urlparse(START_URL).scheme}://{urlparse(START_URL).hostname}"
        end_wait = time.time() + 40
        while time.time() < end_wait:
            u = page.url
            if u.startswith(app_origin) and not is_keycloak_url(u):
                break
            time.sleep(0.5)

        # 5) Persist cookies
        cookies = context.cookies()
        Path("cookies.json").write_text(json.dumps(cookies, indent=2))

        # Filter cookies for APP_HOST for a clean header (typical NextAuth cookie lives on the app host)
        app_cookies = [c for c in cookies if c.get("domain","").lstrip(".") in (APP_HOST,) or c.get("domain","") == f".{APP_HOST}"]
        if not app_cookies:
            # fall back to all cookies if domain scoping is unusual
            app_cookies = cookies

        Path("cookies_header.txt").write_text(cookies_to_header(app_cookies))

        print(f"Wrote {len(cookies)} cookies to cookies.json")
        print(f"Wrote Cookie header for host '{APP_HOST}' to cookies_header.txt")

        browser.close()

if __name__ == "__main__":
    run()
