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
        "risk": "No accountable maintainer remains responsible for security fixes or updates"
    },
    "new_author": {
        "description": "A maintainer appears in this version that was not present in earlier releases",
        "risk": "New maintainers may gain publish access and introduce malicious code"
    },
    "expired_domain": {
        "description": "The maintainer email domain is no longer registered",
        "risk": "Attackers can register the expired domain and intercept password reset emails"
    },
    "deprecated": {
        "description": "The package or version is marked as deprecated in the npm registry",
        "risk": "Deprecated packages often stop receiving security updates"
    },
    "unmaintained": {
        "description": "The package has not received updates for a long period",
        "risk": "Abandoned packages are common targets for takeover attacks"
    },
    "breached_maintainer": {
        "description": "The maintainer email appears in known breach datasets",
        "risk": "Leaked credentials may allow attackers to compromise the maintainer account"
    }
}


def analyze_package(name, version, pkg):

    version_data = get_version(pkg, version)
    #print("version_data :", version_data)

    timeline = sorted(
    pkg["versions"].values(),
    key=lambda v: pkg["time"].get(v.get("version"), "")
)

    email = version_data["_npmUser"]["email"] if "_npmUser" in version_data else None
    #print("email :")
    #print(email)

    raw_signals = {}

    raw_signals["missing_author"] = check_missing_author(version_data)
    raw_signals["new_author"] = detect_new_author(timeline,version_data)
    raw_signals["expired_domain"] = expired_domain(email)
    raw_signals["deprecated"] = detect_deprecated(pkg["versions"])
    raw_signals["unmaintained"] = detect_unmaintained(pkg["time"])

    breach_info = check_breach(email)
    raw_signals["breached_maintainer"] = breach_info["breached"]

    signals = {}

    for key, value in raw_signals.items():
        signals[key] = {
            "value": value,
            "description": SIGNAL_INFO[key]["description"],
            "risk": SIGNAL_INFO[key]["risk"]
        }

    return {
        "package": name,
        "version": version,
        "signals": signals,
        "latest_breach": breach_info["latest_breach"]
    }
