# Maintainer Risk Signal Scanner

The scanner analyzes a specific package version and returns structured security signals.

Example output.

```
{
    "package": "express",
    "version": "4.18.2",
    "signals": {
        "missing_author": 0,
        "new_author": 1,
        "expired_domain": 0,
        "deprecated": 1,
        "unmaintained": 0,
        "breached_maintainer": 0
    },
    "latest_breach": null
}
```

## Purpose

Many supply chain attacks target maintainers.

Attackers gain access to maintainer accounts or publish packages using suspicious identities.

This scanner identifies signals related to maintainer trust and account status.

The signals help downstream risk engines evaluate package safety.

Reference.

https://socket.dev/blog/supply-chain-attacks-in-npm

## Signals

### missing_author

The package version was published by an account that no longer exists.

Reason.

When a maintainer account is deleted there is no accountable maintainer responsible for the package.

Detection method.

Check `_npmUser` of the version and verify that the npm account still exists.

Reference.

https://socket.dev/alerts/missingAuthor

Output.

```
1 = author account missing
0 = author account exists
```

### new_author

Detects the appearance of a new maintainer that was not present in previous versions.

Why it matters.

Many npm supply chain attacks occur after a new maintainer is added to the package.

Example.

event-stream compromise.

Reference.

https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident

Output.

```
1 = new maintainer detected
0 = no change
```

### expired_domain

Checks if the maintainer email domain is expired or no longer registered.

Why it matters.

Attackers can register expired domains and recreate maintainer emails.

Example.

```
maintainer@email-domain.com
```

If the domain expires an attacker can buy it and receive password reset emails.

Reference.

https://www.usenix.org/system/files/sec21fall-liu-yuxing.pdf

Output.

```
1 = domain expired
0 = domain active
```

### deprecated

Detects if the npm package is marked as deprecated.

Deprecated packages often stop receiving security updates.

Detection source.

npm registry metadata.

Reference.

https://docs.npmjs.com/deprecating-and-undeprecating-packages-or-package-versions

Output.

```
1 = deprecated
0 = active
```

### unmaintained

Detects long inactivity in the package release history.

Typical heuristic.

No new release for more than 12 to 24 months.

Abandoned packages are common targets for takeover attacks.

Reference.

https://snyk.io/blog/npm-security-best-practices/

Output.

```
1 = unmaintained
0 = actively maintained
```

### breached_maintainer

Checks if the maintainer email appears in known credential breach datasets.

Example source.

Have I Been Pwned breach corpus.

Reference.

https://haveibeenpwned.com/API/v3

Output.

```
1 = maintainer email appears in breach dataset
0 = no breach found
```

### latest_breach

Stores the most recent breach name affecting the maintainer.

Example.

```
"latest_breach": "LinkedIn"
```

If no breach exists.

```
null
```

## Data Sources

npm registry API.

```
https://registry.npmjs.org/{package}
```

Have I Been Pwned breach API.

```
https://haveibeenpwned.com/API/v3
```

References.

https://docs.npmjs.com/cli/v10/using-npm/registry
https://haveibeenpwned.com/API/v3

## Usage

Run the scanner with a list of package names and versions.

Example.

```
python scan.py packages.json
```

Example input.

```
[
    {"name": "express", "version": "4.18.2"},
    {"name": "lodash", "version": "4.17.21"}
]
```

The scanner fetches metadata from the npm registry and computes maintainer risk signals.

The result is a JSON file containing the extracted signals.

## Output Format

Each record contains.

```
package
version
signals
latest_breach
```

Signals are binary indicators.

```
1 = signal detected
0 = signal not detected
```

The output can feed risk scoring systems

