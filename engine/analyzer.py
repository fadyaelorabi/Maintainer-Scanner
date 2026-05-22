from detectors.missing_author import check_missing_author
from detectors.new_author import detect_new_author
from detectors.expired_domain import expired_domain
from detectors.deprecated import detect_deprecated
from detectors.unmaintained import detect_unmaintained
from detectors.maintainer_breach import check_breach
from utils.version_utils import get_version


SIGNAL_INFO = {
    "missing_author": {
        "description": "The npm account that published this version no longer exists",
        "risk": "No accountable maintainer remains responsible for security fixes or updates",
        "severity_level": "Medium"
    },
    "new_author": {
        "description": "A maintainer appears in this version that was not present in earlier releases",
        "risk": "New maintainers may gain publish access and introduce malicious code",
        "severity_level": "Low"
    },
    "expired_domain": {
        "description": "The maintainer email domain is no longer registered",
        "risk": "Attackers can register the expired domain and intercept password reset emails",
        "severity_level": "High"
    },
    "deprecated": {
        "description": "The package version is marked as deprecated in the npm registry",
        "risk": "Deprecated versions are unsupported and may contain unpatched vulnerabilities",
        "severity_level": "Medium"
    },
    "unmaintained": {
        "description": "The package has not received updates for a long period",
        "risk": "Abandoned packages are common targets for takeover attacks",
        "severity_level": "Low"
    },
    "breached_maintainer": {
        "description": "The maintainer email appears in known breach datasets",
        "risk": "Leaked credentials may allow attackers to compromise the maintainer account",
        "severity_level": "Dynamic"
    }
}


def get_signal_severity(signal_name, signal_value, breach_info=None):
    if not signal_value:
        return "None"

    if signal_name == "breached_maintainer" and breach_info:
        return breach_info.get("severity_level", "Unknown")

    return SIGNAL_INFO[signal_name]["severity_level"]


def analyze_package(name, version, pkg):

    version_data = get_version(pkg, version)

    timeline = sorted(
        pkg["versions"].values(),
        key=lambda v: pkg["time"].get(v.get("version"), "")
    )

    email = version_data["_npmUser"]["email"] if "_npmUser" in version_data else None

    raw_signals = {}

    raw_signals["missing_author"] = check_missing_author(version_data)
    raw_signals["new_author"] = detect_new_author(timeline, version_data)
    raw_signals["expired_domain"] = expired_domain(email)
    raw_signals["deprecated"] = detect_deprecated(version_data)
    raw_signals["unmaintained"] = detect_unmaintained(pkg["time"])

    breach_info = check_breach(email)
    raw_signals["breached_maintainer"] = breach_info.get("breached", 0)

    signals = {}

    for key, value in raw_signals.items():
        signals[key] = {
            "value": value,
            "description": SIGNAL_INFO[key]["description"],
            "risk": SIGNAL_INFO[key]["risk"],
            "severity_level": get_signal_severity(
                key,
                value,
                breach_info=breach_info
            )
        }

    return {
        "package": name,
        "version": version,
        "signals": signals,
        "latest_breach": breach_info.get("latest_breach"),
        "breach_severity_level": breach_info.get("severity_level", "None")
    }
