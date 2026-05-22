import requests
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("HIBP_API_KEY")

HIJACK_DATA = {
    "passwords",
    "auth tokens",
    "api keys",
    "credential pairs"
}


def calculate_breach_severity(breach_date, package_abandoned=False):
    breach_dt = datetime.strptime(breach_date, "%Y-%m-%d")
    now = datetime.utcnow()

    age_days = (now - breach_dt).days
    age_years = age_days / 365.25

    if age_years <= 1:
        severity_level = "High"
        breach_age_weight = "High"

    elif age_years <= 3:
        severity_level = "Medium"
        breach_age_weight = "Medium"

    elif age_years <= 7:
        severity_level = "Low"
        breach_age_weight = "Low"

    else:
        if package_abandoned:
            severity_level = "Medium"
            breach_age_weight = "Very low, but raised because package is abandoned"
        else:
            severity_level = "Very Low"
            breach_age_weight = "Very low"

    return {
        "breach_age_days": age_days,
        "breach_age_years": round(age_years, 2),
        "breach_age_weight": breach_age_weight,
        "severity_level": severity_level
    }


def check_breach(email, package_abandoned=False):
    API_KEY = os.getenv("HIBP_API_KEY")

    if not API_KEY:
        return {
            "breached": 0,
            "latest_breach": None,
            "severity_level": "Unknown",
            "error": "Missing HIBP API key"
        }

    if not email:
        return {
            "breached": 0,
            "latest_breach": None,
            "severity_level": "Unknown",
            "error": "Missing email"
        }

    headers = {
        "hibp-api-key": API_KEY,
        "user-agent": "depscan"
    }

    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"

    try:
        r = requests.get(url, headers=headers, timeout=5)

        if r.status_code == 404:
            return {
                "breached": 0,
                "latest_breach": None,
                "severity_level": "None",
                "error": None
            }

        if r.status_code != 200:
            return {
                "breached": 0,
                "latest_breach": None,
                "severity_level": "Unknown",
                "error": f"HIBP API error: status code {r.status_code}"
            }

        breaches = r.json()

        credential_breaches = []

        for b in breaches:
            exposed = [d.lower() for d in b.get("DataClasses", [])]

            if any(d in HIJACK_DATA for d in exposed):
                credential_breaches.append(b)

        if not credential_breaches:
            return {
                "breached": 0,
                "latest_breach": None,
                "severity_level": "None",
                "error": None
            }

        latest = max(
            credential_breaches,
            key=lambda b: datetime.strptime(b["BreachDate"], "%Y-%m-%d")
        )

        severity = calculate_breach_severity(
            latest["BreachDate"],
            package_abandoned=package_abandoned
        )

        latest_breach = {
            "name": latest["Name"],
            "breach_date": latest["BreachDate"],
            "data_exposed": latest["DataClasses"],
            "breach_age_days": severity["breach_age_days"],
            "breach_age_years": severity["breach_age_years"],
            "breach_age_weight": severity["breach_age_weight"],
            "severity_level": severity["severity_level"]
        }

        return {
            "breached": 1,
            "latest_breach": latest_breach,
            "severity_level": severity["severity_level"],
            "error": None
        }

    except requests.RequestException as e:
        return {
            "breached": 0,
            "latest_breach": None,
            "severity_level": "Unknown",
            "error": str(e)
        }

    except ValueError as e:
        return {
            "breached": 0,
            "latest_breach": None,
            "severity_level": "Unknown",
            "error": f"Invalid breach date format: {str(e)}"
        }
