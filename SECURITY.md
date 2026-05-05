# Security Policy

## Reporting a vulnerability

**Do not** file a public GitHub issue for a security vulnerability in pqcscan.

Email: **tools@orengacademy.com** with subject prefix `[pqcscan-security]`.

Please include:

- A description of the issue and its impact.
- Steps to reproduce, or proof-of-concept code.
- Affected version(s) (`git rev-parse HEAD` or release tag).
- Your name + handle for credit (or "anonymous" if you prefer).

We aim to acknowledge within **5 business days** and ship a fix within
**30 days** for high-severity issues. We coordinate disclosure with the
reporter and prefer responsible disclosure of full details after a patch
ships.

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅                 |
| < 0.1   | ❌ (pre-release)   |

## Threat model

pqcscan is **read-only** by design — it scans local config and binaries,
queries network endpoints, and reads dep-lock files. It does not write to
the host (other than its own SQLite DB and exports) and does not exfiltrate
data.

The web UI binds **127.0.0.1 by default** with no authentication. The
trust boundary is OS-level access to the host running the daemon. If you
expose the daemon outside `127.0.0.1`, put it behind a reverse proxy
with TLS and auth — there is no built-in auth layer.

Probes that need root (e.g. `host.lynis`) auto-skip when run as a non-root
user, with an INFO finding noting the gap.

## Things that are **not** vulnerabilities

- A probe finding flags a real-world vulnerable algorithm (RC4, MD5, RSA-1024,
  etc.) on your host. That's the tool **working correctly** — fix the
  configuration.
- The OSV matcher reports CVEs in your locked dependencies. Same — that's
  the tool working correctly. Update your deps.
- The compliance engine emits a `non-compliant` verdict against a framework.
  Same — adjust your configuration to match the framework.

## Handling secrets in evidence

`secrets.gitleaks` and `app.dotenv.secrets` deliberately **redact** secret
values in their `evidence` dict (storing only `secret_redacted: True` and
`length`). If you find a probe leaking real secret content into a Finding's
evidence, **that is a vulnerability** — please report it.
