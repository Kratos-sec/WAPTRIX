"""One-time database setup for the benchmark apps. Run inside the api container (it is on the lab network):

    docker compose -f docker-compose.yml -f docker-compose.lab.yml exec api python /lab/bootstrap.py

Only talks to *.waptrix.lab hosts on the internal lab network. Idempotent: re-running resets the
application databases to their shipped state, which is what each benchmark repetition should start from.
"""

from __future__ import annotations

import re
import sys
import time

import httpx

LAB = "waptrix.lab"


def wait(client: httpx.Client, url: str, attempts: int = 60) -> None:
    for _ in range(attempts):
        try:
            if client.get(url).status_code < 500:
                return
        except httpx.HTTPError:
            pass
        time.sleep(2)
    raise SystemExit(f"{url} did not come up")


def dvwa(client: httpx.Client) -> str:
    base = f"http://dvwa.{LAB}"
    wait(client, f"{base}/setup.php")
    page = client.get(f"{base}/setup.php").text
    token = re.search(r"name='user_token' value='([0-9a-f]+)'", page)
    data = {"create_db": "Create / Reset Database"}
    if token:
        data["user_token"] = token.group(1)
    client.post(f"{base}/setup.php", data=data)
    return "database created (login admin / password, then set security level as required)"


def bwapp(client: httpx.Client) -> str:
    base = f"http://bwapp.{LAB}"
    wait(client, f"{base}/install.php")
    client.get(f"{base}/install.php", params={"install": "yes"})
    return "installed (login bee / bug)"


def mutillidae(client: httpx.Client) -> str:
    base = f"http://mutillidae.{LAB}"
    wait(client, f"{base}/")
    client.get(f"{base}/set-up-database.php")
    return "database set up"


def wait_only(host: str, path: str = "/"):
    def run(client: httpx.Client) -> str:
        wait(client, f"http://{host}.{LAB}{path}")
        return "up"
    return run


STEPS = {
    "dvwa": dvwa,
    "bwapp": bwapp,
    "mutillidae": mutillidae,
    "juiceshop": wait_only("juiceshop"),
    "webgoat": wait_only("webgoat", "/WebGoat/login"),
}


def main(argv: list[str]) -> int:
    wanted = argv or list(STEPS)
    for name in wanted:
        with httpx.Client(timeout=30, follow_redirects=True) as client:
            print(f"{name}: {STEPS[name](client)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
