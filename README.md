### Example Scan Result

The scanner returns a structured JSON object describing the analyzed package version and detected maintainer risk signals.

Example.

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
    "latest_breach": {
         "name": "LinkedIn",
         "breach_date": "2012-05-05",
         "records_exposed": 164611595,
         "data_exposed": [ "Email addresses", "Passwords" ]
}
}
```

Field explanation.

package
Name of the analyzed npm package.

version
Specific version that was evaluated.

signals
Binary indicators describing detected maintainer related risks.

Signal values.

```
0 = signal not detected
1 = signal detected
```

missing_author
Indicates whether the publishing npm account no longer exists.

new_author
Indicates that the publishing maintainer was not present in earlier package versions.

expired_domain
Checks whether the maintainer email domain is no longer registered.

deprecated
Indicates that the package version is marked as deprecated in the npm registry.

unmaintained
Indicates long inactivity in package releases.

breached_maintainer
Indicates that the maintainer email appears in known breach datasets.

latest_breach
Stores details about the most recent breach affecting the maintainer email.

If no breach is found the value is:

```
null
```

References.

npm registry API
https://docs.npmjs.com/cli/v10/using-npm/registry

Have I Been Pwned breach API
https://haveibeenpwned.com/API/v3
