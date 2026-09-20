# Privacy

Android bugreports and exploit logs are private diagnostic material. They may
contain account identifiers, network names, nearby devices, application data,
hardware identifiers, device serials, boot IDs, host paths, and live kernel
addresses.

## Default handling

The runner creates its output directory with mode 0700. A newly captured
bugreport stays inside that directory only long enough to extract a boot-bound
KASLR result and is then deleted. The repository receives no telemetry and
makes no network request.

`--retain-bugreport` is intended for private local debugging. Do not attach a
retained archive to an issue or release.

## Sharing a report

Generate a reduced JSON report:

```sh
./ghostlock report PRIVATE_RUN_DIRECTORY --output ghostlock-report.json
```

The redactor includes target compatibility fields, high-level gate results,
anchor symbol names, success booleans, and fixed monotonic durations for the
preflight, exploit, verification, and total run. Arbitrary timing keys from a
private manifest are not copied. It omits:

- device serial and boot identity;
- absolute host paths;
- raw command output;
- raw bugreport content;
- KASLR slides, kernel pointers, and PFNs;
- the acceptance transcript.

Review the generated file manually before sharing it. Redaction is a
data-minimization aid, not a guarantee that arbitrary future fields are safe.

## Material that does not belong in this repository

Never commit or upload:

- ADB private keys or authorized-key databases;
- eMMC, boot, vendor, system, userdata, modem, or secure-partition images;
- full symbol tables or decompiler databases;
- bugreports, logcat archives, crash dumps, screenshots, or run directories;
- serials, IMEI/EID/ICCID values, MAC addresses, phone numbers, or account IDs.

The release audit rejects common forms of this material before publication.
