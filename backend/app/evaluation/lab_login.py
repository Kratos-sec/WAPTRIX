"""Hardcoded logins for the lab apps, so scans run with a session instead of stopping at the login page.

Default credentials only (the apps ship with them). Each recipe returns a Cookie header value or None.
Lab use only: these hostnames exist only on the internal lab network.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable

import httpx

logger = logging.getLogger("waptrix.lab")

WEBGOAT_USER = "waptrix"
WEBGOAT_PASSWORD = "waptrix123"


def _cookie(client: httpx.Client, name: str, extra: dict[str, str] | None = None) -> str | None:
    value = client.cookies.get(name)
    if not value:
        return None
    parts = [f"{name}={value}", *(f"{k}={v}" for k, v in (extra or {}).items())]
    return "; ".join(parts)


def dvwa(client: httpx.Client, base: str) -> str | None:
    page = client.get(f"{base}/login.php").text
    token = re.search(r"name='user_token' value='([0-9a-f]+)'", page)
    data = {"username": "admin", "password": "password", "Login": "Login"}
    if token:
        data["user_token"] = token.group(1)
    resp = client.post(f"{base}/login.php", data=data)
    if "login.php" in str(resp.url):
        return None
    client.cookies.set("security", "low")
    return _cookie(client, "PHPSESSID", {"security": "low"})


def bwapp(client: httpx.Client, base: str) -> str | None:
    resp = client.post(f"{base}/login.php", data={"login": "bee", "password": "bug", "security_level": "0",
                                                   "form": "submit"})
    if "login.php" in str(resp.url):
        return None
    return _cookie(client, "PHPSESSID", {"security_level": "0"})


def webgoat(client: httpx.Client, base: str) -> str | None:
    # Registering an existing user just fails; either way the login below works.
    client.post(f"{base}/WebGoat/register.mvc", data={
        "username": WEBGOAT_USER, "password": WEBGOAT_PASSWORD, "matchingPassword": WEBGOAT_PASSWORD,
        "agree": "agree"})
    client.cookies.clear()
    resp = client.post(f"{base}/WebGoat/login", data={"username": WEBGOAT_USER, "password": WEBGOAT_PASSWORD})
    if "error" in str(resp.url) or "login" in str(resp.url).rsplit("/", 1)[-1]:
        return None
    return _cookie(client, "JSESSIONID")


RECIPES: dict[str, Callable[[httpx.Client, str], str | None]] = {"dvwa": dvwa, "bwapp": bwapp, "webgoat": webgoat}


def login(app_id: str, host: str, timeout: float = 30.0) -> str | None:
    """Log in to a lab app and return its session cookie; None if the app needs none or login failed."""
    recipe = RECIPES.get(app_id)
    if recipe is None:
        return None
    try:
        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            cookie = recipe(client, f"http://{host}")
    except httpx.HTTPError as exc:
        logger.warning("lab login for %s failed: %s", app_id, exc)
        return None
    if cookie is None:
        logger.warning("lab login for %s did not yield a session", app_id)
    return cookie


__all__ = ["login", "RECIPES"]
