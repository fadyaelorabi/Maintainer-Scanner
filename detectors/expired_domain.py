import requests
import os

RAPID_API_KEY = os.getenv("X-RapidAPI-Key")

def expired_domain(email):

    if not email:
        return 0

    if "@" not in email:
        return 0

    domain = email.split("@")[1]

    COMMON_PROVIDERS = {
        "gmail.com",
        "outlook.com",
        "yahoo.com",
        "proton.me"
    }

    if domain in COMMON_PROVIDERS:
        return 0

    url = "https://whois-lookup10.p.rapidapi.com/api.php"

    query = {"domain": domain}

    headers = {
        "X-RapidAPI-Key": RAPID_API_KEY,
        "X-RapidAPI-Host": "whois-lookup10.p.rapidapi.com"
    }

    try:

        r = requests.get(url, headers=headers, params=query, timeout=10)

        if r.status_code != 200:
            return 0

        data = r.json()

        status = data.get("status", "").lower()

        if "available" in status or "free" in status:
            return 1

    except Exception:
        return 0

    return 0