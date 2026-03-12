# Maintainer Scanner

Maintainer Scanner analyzes npm packages and extracts maintainer related security signals that indicate potential supply chain risk.

The system focuses on maintainer identity, account security, and package maintenance status.

The scanner queries the npm registry and external breach intelligence sources to identify indicators that may lead to package compromise.

---

# Purpose

Many software supply chain attacks originate from compromised maintainer accounts.

Attack scenarios commonly include.

• attacker gains access to maintainer credentials
• attacker publishes a malicious version
• downstream projects install the compromised package

The scanner identifies early indicators that increase the probability of maintainer compromise.

Examples.

• new maintainers appearing in the release history
• maintainer emails exposed in credential breaches
• abandoned or deprecated packages
• expired maintainer email domains

---

# Architecture

Pipeline.

```
npm registry → package metadata → signal detectors → structured output signals.
```

The scanner evaluates a specific package version and returns structured signals.

Example result.

```
{
  "package": "express",
  "version": "4.18.2",
  "signals": {
    "missing_author": {
      "value": 0,
      "description": "...",
      "risk": "..."
    },
    "new_author": {
      "value": 1,
      "description": "...",
      "risk": "..."
    }
  },
  "latest_breach": null
}
```

Signal values.

```
0 = condition not detected
1 = condition detected
```

---

# Signals

## missing_author

Description.

The npm account that published the analyzed version no longer exists.

Detection.

The scanner checks the `_npmUser` metadata for the version.

Risk.

When the publisher account disappears there is no accountable maintainer responsible for fixing vulnerabilities or publishing secure updates.

---

## new_author

Description.

A maintainer appears in the package timeline that did not publish earlier versions.

Detection.

The scanner compares maintainers across the version history.

Risk.

Attackers frequently gain publish access as new maintainers and introduce malicious code.

Example attack.

event-stream compromise.

---

## expired_domain

Description.

The maintainer email domain is no longer registered.

Detection.

The scanner extracts the domain from the maintainer email and checks domain registration.

Risk.

Attackers can purchase expired domains and intercept password reset emails to take over maintainer accounts.

---

## deprecated

Description.

The package version is marked as deprecated in the npm registry.

Detection.

The scanner checks the `deprecated` field in the version metadata.

Risk.

Deprecated packages often stop receiving updates and security fixes.

---

## unmaintained

Description.

The package has not received updates for a long period.

Detection.

The scanner analyzes the publish timeline using the `time` metadata.

Risk.

Abandoned packages become attractive takeover targets.

---

## breached_maintainer

Description.

The maintainer email appears in known breach datasets.

Detection.

The scanner queries the breach intelligence database.

Only breaches exposing **credential related data** are considered.

Examples of credential data.

```
Passwords
Auth tokens
API keys
Credential pairs
```

Breaches containing only informational data are ignored.

Examples ignored.

```
Email addresses
Usernames
Names
```

Risk.

Leaked credentials enable attackers to perform credential stuffing and gain access to maintainer accounts.

Reference.
https://haveibeenpwned.com/API/v3

---

# latest_breach

If a maintainer email appears in a credential exposing breach, the scanner records the most recent breach.

Structure.

```
{
  "name": "LinkedIn",
  "breach_date": "2012-05-05",
  "data_exposed": [
    "Email addresses",
    "Passwords"
  ]
}
```

Fields.

name
Name of the breached service.

breach_date
Date when the breach occurred.

data_exposed
Types of data leaked.

If no credential exposing breach exists.

```
latest_breach = null
```

---

# Data Sources

npm registry.

```
https://registry.npmjs.org/{package}
```

Breach intelligence.

```
https://haveibeenpwned.com/api/v3
```

References.

https://docs.npmjs.com/cli/v10/using-npm/registry
https://haveibeenpwned.com/API/v3
https://rapidapi.com/logicbuilder/api/whois-lookup10
https://arxiv.org/pdf/2112.10165


---

# Running the Scanner

Install dependencies.

```
pip install fastapi uvicorn requests
```

Run the API.

```
uvicorn api:app --reload
```

Example request.

```
GET /scan?package=express&version=4.18.2
```

The API returns a structured security analysis for the specified package version.

---

# License

MIT

# Setup

Clone the repository from GitHub.

```
git clone https://github.com/fadyaelorabi/Maintainer-Scanner.git
cd Maintainer-Scanner
```

Create a virtual environment.

```
python -m venv venv
```

Activate the virtual environment.

Windows.

```
venv\Scripts\activate
```

Install project dependencies.

If a requirements file exists.

```
pip install -r requirements.txt
```

If not, install the required libraries manually.

```
pip install fastapi uvicorn requests python-dotenv
```

---

# Environment Variables

The scanner requires API keys for external services.

Set the following environment variables.

Windows.

```
set HIBP_API_KEY=your_hibp_api_key
set RAPIDAPI_KEY=your_rapidapi_key
```

HIBP API reference.
https://haveibeenpwned.com/API/v3

RapidAPI WHOIS service.
https://rapidapi.com/logicbuilder/api/whois-lookup10

---

# Running the API

Start the FastAPI server.

```
uvicorn api:app --reload
```

Alternative method.

```
python -m uvicorn api:app --reload
```

The API server will start at.

```
http://127.0.0.1:8000
```

---

# Testing the API

Open the interactive API documentation.

```
http://127.0.0.1:8000/docs
```

Example request.

```
/scan?package=express&version=4.18.2
```

The API returns a structured JSON report containing maintainer risk signals and breach information.

