# Maintainer Scanner API Documentation

Maintainer Scanner analyzes an npm package version and returns maintainer risk signals related to account ownership, package maintenance, breach exposure, and takeover risk.

The API returns a structured JSON report for the selected package and version.

---

# Full API Response Structure

## Example Response

```json
{
  "package": "express",
  "version": "4.18.2",
  "signals": {
    "missing_author": {
      "value": 0,
      "description": "The npm account that published this version no longer exists",
      "risk": "No accountable maintainer remains responsible for security fixes or updates",
      "severity_level": "None"
    },
    "new_author": {
      "value": 1,
      "description": "A maintainer appears in this version that was not present in earlier releases",
      "risk": "New maintainers may gain publish access and introduce malicious code",
      "severity_level": "Medium"
    },
    "expired_domain": {
      "value": 0,
      "description": "The maintainer email domain is no longer registered",
      "risk": "Attackers can register the expired domain and intercept password reset emails",
      "severity_level": "None"
    },
    "deprecated": {
      "value": 1,
      "description": "The package or version is marked as deprecated in the npm registry",
      "risk": "Deprecated packages often stop receiving security updates",
      "severity_level": "Low"
    },
    "unmaintained": {
      "value": 0,
      "description": "The package has not received updates for a long period",
      "risk": "Abandoned packages are common targets for takeover attacks",
      "severity_level": "None"
    },
    "breached_maintainer": {
      "value": 1,
      "description": "The maintainer email appears in known breach datasets",
      "risk": "Leaked credentials may allow attackers to compromise the maintainer account",
      "severity_level": "Very Low"
    }
  },
  "latest_breach": {
    "name": "LinkedIn",
    "breach_date": "2012-05-05",
    "data_exposed": [
      "Email addresses",
      "Passwords"
    ],
    "breach_age_days": 5128,
    "breach_age_years": 14.04,
    "breach_age_weight": "Very low",
    "severity_level": "Very Low"
  },
  "breach_severity_level": "Very Low"
}
```

---

# Response Fields

## package

Name of the analyzed npm package.

Example:

```json
"package": "express"
```

## version

Specific package version analyzed by the scanner.

Example:

```json
"version": "4.18.2"
```

## signals

Security indicators related to maintainer identity, account safety, package maintenance, and breach exposure.

Each signal contains:

| Field | Meaning |
|---|---|
| `value` | Binary detection result |
| `description` | Explanation of what the signal detects |
| `risk` | Security impact of the signal |
| `severity_level` | Severity assigned to the signal |

---

# Signal Value Rules

```text
0 = condition not detected
1 = condition detected
```

When a signal value is `0`, its severity is always:

```json
"severity_level": "None"
```

When a signal value is `1`, its severity depends on the signal type.

---

# Severity Level Rules

## Fixed Severity Signals

These signals use fixed severity when active.

| Signal | Active Severity |
|---|---|
| `missing_author` | High |
| `new_author` | Medium |
| `expired_domain` | High |
| `deprecated` | Low |
| `unmaintained` | Medium |

Example:

```json
"missing_author": {
  "value": 1,
  "description": "The npm account that published this version no longer exists",
  "risk": "No accountable maintainer remains responsible for security fixes or updates",
  "severity_level": "High"
}
```

If the same signal is inactive:

```json
"missing_author": {
  "value": 0,
  "description": "The npm account that published this version no longer exists",
  "risk": "No accountable maintainer remains responsible for security fixes or updates",
  "severity_level": "None"
}
```

---

# Dynamic Severity Signal

## breached_maintainer

The `breached_maintainer` signal does not use fixed severity.

Its severity is calculated from the age of the most recent credential exposing breach.

| Breach Age | Severity |
|---|---|
| 0 to 1 year | High |
| 2 to 3 years | Medium |
| 4 to 7 years | Low |
| More than 7 years | Very Low |
| More than 7 years and package is abandoned | Raised severity |

Example:

```json
"breached_maintainer": {
  "value": 1,
  "description": "The maintainer email appears in known breach datasets",
  "risk": "Leaked credentials may allow attackers to compromise the maintainer account",
  "severity_level": "Very Low"
}
```

The value above means the maintainer email appears in a credential exposing breach, but the breach is old.

---

# Signals

## missing_author

### Description

The npm account that published the analyzed version no longer exists.

### Detection

The scanner checks the `_npmUser` metadata for the analyzed version.

### Risk

When the publisher account disappears, no accountable npm account remains clearly responsible for security fixes or future updates.

### Severity

```text
High when detected.
None when not detected.
```

---

## new_author

### Description

A maintainer appears in this version but was not present in earlier releases.

### Detection

The scanner compares maintainers across the package version timeline.

### Risk

New maintainers can gain publish access and introduce malicious code.

### Example Attack

```text
event-stream compromise
```

### Severity

```text
Medium when detected.
None when not detected.
```

---

## expired_domain

### Description

The maintainer email domain is no longer registered.

### Detection

The scanner extracts the domain from the maintainer email and checks domain registration status.

### Risk

Attackers can register expired domains and intercept password reset emails.

This can lead to maintainer account takeover.

### Severity

```text
High when detected.
None when not detected.
```

---

## deprecated

### Description

The package or package version is marked as deprecated in the npm registry.

### Detection

The scanner checks the `deprecated` field in the package version metadata.

### Risk

Deprecated packages often stop receiving updates and security fixes.

### Severity

```text
Low when detected.
None when not detected.
```

---

## unmaintained

### Description

The package has not received updates for a long period.

### Detection

The scanner analyzes the package publish timeline using the `time` metadata from the npm registry.

### Risk

Abandoned packages become attractive takeover targets.

### Severity

```text
Medium when detected.
None when not detected.
```

---

## breached_maintainer

### Description

The maintainer email appears in known breach datasets.

### Detection

The scanner queries the breach intelligence database.

Only breaches exposing credential related data are considered.

### Credential Related Data

```text
Passwords
Auth tokens
API keys
Credential pairs
```

### Ignored Data Types

Breaches containing only informational data are ignored.

```text
Email addresses
Usernames
Names
```

### Risk

Leaked credentials can allow attackers to perform credential stuffing and compromise maintainer accounts.

### Severity

The severity is dynamic.

It depends on the age of the most recent credential exposing breach.

```text
0 to 1 year = High
2 to 3 years = Medium
4 to 7 years = Low
More than 7 years = Very Low
```

If the package is abandoned, old breach severity can be raised.

---

# latest_breach

If a maintainer email appears in a credential exposing breach, the scanner records the most recent credential related breach.

## Structure

```json
{
  "name": "LinkedIn",
  "breach_date": "2012-05-05",
  "data_exposed": [
    "Email addresses",
    "Passwords"
  ],
  "breach_age_days": 5128,
  "breach_age_years": 14.04,
  "breach_age_weight": "Very low",
  "severity_level": "Very Low"
}
```

## Fields

| Field | Meaning |
|---|---|
| `name` | Name of the breached service |
| `breach_date` | Date when the breach occurred |
| `data_exposed` | Types of data leaked |
| `breach_age_days` | Number of days since the breach |
| `breach_age_years` | Number of years since the breach |
| `breach_age_weight` | Text label for breach age weight |
| `severity_level` | Severity calculated from breach age |

## No Breach Case

If no credential exposing breach exists:

```json
"latest_breach": null
```

The top level breach severity becomes:

```json
"breach_severity_level": "None"
```

---

# breach_severity_level

This field summarizes the severity of the latest credential exposing breach.

Example:

```json
"breach_severity_level": "Very Low"
```

If no credential exposing breach exists:

```json
"breach_severity_level": "None"
```

---

# Data Sources

## npm Registry

Used to retrieve package metadata, versions, maintainers, publish dates, and deprecation status.

```text
https://registry.npmjs.org/{package}
```

## Breach Intelligence

Used to check whether maintainer emails appear in known credential exposing breaches.

```text
https://haveibeenpwned.com/api/v3
```

## Domain Registration Lookup

Used to check whether maintainer email domains are still registered.

```text
RapidAPI WHOIS lookup
```

---

# References

```text
https://docs.npmjs.com/cli/v10/using-npm/registry
https://haveibeenpwned.com/API/v3
https://rapidapi.com/logicbuilder/api/whois-lookup10
https://arxiv.org/pdf/2112.10165
```

---

# Running the Scanner

## Install Dependencies

```bash
pip install fastapi uvicorn requests python-dotenv
```

## Run the API

```bash
uvicorn api:app --reload
```

Alternative command:

```bash
python -m uvicorn api:app --reload
```

The API server starts at:

```text
http://127.0.0.1:8000
```

---

# Example Request

```http
GET /scan?package=express&version=4.18.2
```

Full local URL:

```text
http://127.0.0.1:8000/scan?package=express&version=4.18.2
```

---

# Setup

## Clone the Repository

```bash
git clone https://github.com/fadyaelorabi/Maintainer-Scanner.git
cd Maintainer-Scanner
```

## Create a Virtual Environment

```bash
python -m venv venv
```

## Activate the Virtual Environment

Windows:

```bash
venv\\Scripts\\activate
```

Linux or macOS:

```bash
source venv/bin/activate
```

## Install Project Dependencies

If a requirements file exists:

```bash
pip install -r requirements.txt
```

If no requirements file exists:

```bash
pip install fastapi uvicorn requests python-dotenv
```

---

# Environment Variables

The scanner requires API keys for external services.

## Windows CMD

```cmd
set HIBP_API_KEY=your_hibp_api_key
set RAPIDAPI_KEY=your_rapidapi_key
```

## Windows PowerShell

```powershell
$env:HIBP_API_KEY="your_hibp_api_key"
$env:RAPIDAPI_KEY="your_rapidapi_key"
```

## Linux or macOS

```bash
export HIBP_API_KEY=your_hibp_api_key
export RAPIDAPI_KEY=your_rapidapi_key
```

---

# Testing the API

Open the FastAPI interactive documentation:

```text
http://localhost:8000/docs
```

Test the scan endpoint directly:

```text
http://localhost:8000/scan?package=express&version=4.18.2
```

---

# API Contract Summary

The API response must include:

```text
package
version
signals
latest_breach
breach_severity_level
```

Each signal must include:

```text
value
description
risk
severity_level
```

The `breached_maintainer` signal must use dynamic severity from the breach age formula.

Inactive signals must always return:

```json
"severity_level": "None"
```

---

# Design Notes

The scanner separates detection from explanation.

Detector functions return raw binary values.

Example:

```json
"missing_author": 1
```

The analyzer converts raw values into readable API output.

Example:

```json
"missing_author": {
  "value": 1,
  "description": "The npm account that published this version no longer exists",
  "risk": "No accountable maintainer remains responsible for security fixes or updates",
  "severity_level": "High"
}
```

This structure helps the frontend display clear security reports without needing to know detector internals.
