# Security Policy

## Supported versions

| Version | Supported |
|---|---|
| latest release | yes |
| older releases | no |

## Reporting a vulnerability

Open a GitHub security advisory (Security → Report a vulnerability) or
email the maintainer. Do not open a public issue with exploit details.

Please include: the affected component (broker / core / bindings), a
minimal reproduction (a script is ideal — the `experiments/` harness is
a good template), and the impact you see.

## Threat model notes

* Identity is a shared-secret HMAC token (`AUTH`); the broker derives
  the AG-ID from the token, so a stolen NICK is worthless without the
  key. Rotate keys to revoke.
* Link peers (federation) are **trusted by address** — do not point
  `--peer` at an untrusted host.
* The audit log is hash-chained to detect tampering, not to prevent it;
  ship it somewhere else if you need non-repudiation.
* Store-and-forward queues are bounded (256 per agent, 15 min TTL) to
  limit memory pressure from forged destinations.
