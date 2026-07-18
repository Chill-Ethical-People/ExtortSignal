# Security policy

## Supported version

ExtortSignal is currently a pre-1.0 project. Security fixes are applied to the
latest published version only.

## Reporting a vulnerability

Please use the hosting repository's private security-advisory feature. Do not
open a public issue containing an exploit, client profile, API key, `.env`
content, database, raw observation, DLS address, or screenshot of sensitive
operational data.

Include the affected version, reproduction steps, impact, and a minimal test
case with synthetic `.example` data. Maintainers should acknowledge a complete
report within seven days and coordinate disclosure after a fix is available.

## Deployment boundary

ExtortSignal has no built-in user authentication. The supported default is
localhost-only operation. Do not expose the application directly to a LAN or
the internet. Direct-site activity must run from an isolated, allowlisted Kali
worker and must never download leaks, authenticate, submit forms, or contact
threat actors.
