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

The web UI binds **127.0.0.1 by default**. Without a token the trust
boundary is OS-level access to the host running the daemon. `pqcscan daemon
--token …` (or `$PQCSCAN_TOKEN`) requires a bearer token / login cookie on
every request, and the daemon **refuses a non-loopback `--bind` without
one**. State-changing requests are rejected when a browser `Origin` does
not match the `Host` (CSRF). Serve HTTPS with `--tls-cert`/`--tls-key` or expose it
only behind a TLS-terminating reverse proxy. The SQLite DB is created `0600`.

Probes that need root (e.g. `fs.cert.privkey`, `storage.luks.headers`)
auto-skip when run as a non-root user, with an INFO finding noting the gap.

## Things that are **not** vulnerabilities

- A probe finding flags a real-world vulnerable algorithm (RC4, MD5, RSA-1024,
  etc.) on your host. That's the tool **working correctly** — fix the
  configuration.
- The compliance engine emits a `non-compliant` verdict against a framework.
  Same — adjust your configuration to match the framework.

## Handling secrets in evidence

Probes that touch key material (`fs.cert.privkey`, `fs.db.crypto`,
`fs.cert.privkey_encrypted`, …) record only the algorithm, size and
location — never the key bytes. If you find a probe leaking private-key or
secret content into a Finding's evidence, **that is a vulnerability** —
please report it.
