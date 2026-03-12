import requests
import os
from datetime import datetime

API_KEY = os.getenv("HIBP_API_KEY")

HIJACK_DATA = {
    "passwords",
    "auth tokens",
    "api keys",
    "credential pairs"
}


def check_breach(email):

    if not email:
        return {
            "breached": 0,
            "latest_breach": None
        }

    headers = {
        "hibp-api-key": API_KEY,
        "user-agent": "depscan"
    }

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"

    try:

        r = requests.get(url, headers=headers, timeout=5)

        if r.status_code != 200:
            return {
                "breached": 0,
                "latest_breach": None
            }

        breaches = r.json()

        credential_breaches = []

        for b in breaches:

            exposed = [d.lower() for d in b["DataClasses"]]

            if any(d in HIJACK_DATA for d in exposed):
                credential_breaches.append(b)

        if not credential_breaches:
            return {
                "breached": 0,
                "latest_breach": None
            }

        latest = max(
            credential_breaches,
            key=lambda b: datetime.strptime(b["BreachDate"], "%Y-%m-%d")
        )

        latest_breach = {
            "name": latest["Name"],
            "breach_date": latest["BreachDate"],
            "data_exposed": latest["DataClasses"]
        }

        return {
            "breached": 1,
            "latest_breach": latest_breach
        }

    except:
        return {
            "breached": 0,
            "latest_breach": None
        }
