import requests
import os
from datetime import datetime

API_KEY = os.getenv("HIBP_API_KEY")


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

        latest = max(
            breaches,
            key=lambda b: datetime.strptime(b["BreachDate"], "%Y-%m-%d")
        )

        latest_breach = {
            "name": latest["Name"],
            "breach_date": latest["BreachDate"],
            "records_exposed": latest["PwnCount"],
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