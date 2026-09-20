# Security policy

## Supported versions

| Version | Security fixes |
| --- | --- |
| 0.1.x | Supported |
| Unreleased snapshots | Best effort |

## Reporting a vulnerability

Use GitHub's **Security → Report a vulnerability** form for vulnerabilities in
the runner, command broker, release workflow, or repository supply chain. Do
not open a public issue for a vulnerability that would expose users.

Include a minimal reproduction and the affected commit. Do not attach a raw
bugreport, run directory, firmware image, ADB key, device identifier, or live
kernel address. A redacted report from `./ghostlock report` is welcome when
it is relevant.

## Reporting harmful use

For a concern that this repository or a fork is being used to harm others,
open a minimal issue titled `Abuse report` without victim data or operational
details. If the report itself is sensitive, use the private vulnerability
reporting form.

This project is intended for user-owned device research and recovery. It does
not provide ADB authorization material, persistence, credential collection,
telemetry, remote control, or target discovery.
