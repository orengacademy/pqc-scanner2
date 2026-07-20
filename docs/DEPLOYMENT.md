# Production deployment (Linux / systemd)

This guide deploys the `pqcscan` daemon as a hardened systemd service on a
Linux host (tested target: RHEL / Oracle Linux 7.9–9). It uses the prebuilt
single-file binary from GitHub Releases — no Python, pip, or `ssl` module on
the host is required.

> **Why the binary, not `pip install`?** The editable dev install
> (`pip install -e ".[dev]"`) needs a Python interpreter with a working `_ssl`
> extension to fetch build deps from PyPI. Hosts whose `python3.11` was built
> without OpenSSL headers fail at install time. The frozen binary sidesteps
> Python entirely.

---

## Security model — read before exposing anything

The daemon ships with **no authentication**, **no CORS / Host filtering**, and
serves **plain HTTP** (no TLS). `POST /api/scans` lets any client that can
reach the port trigger scans and read every finding.

The only thing protecting it out of the box is the default `127.0.0.1` bind.

- **Do** keep `--bind 127.0.0.1`. Reach the UI over an SSH tunnel, or front it
  with a reverse proxy that terminates TLS and enforces auth (see below).
- **Do not** pass `--bind 0.0.0.0` (or a LAN address) without that proxy. Doing
  so publishes an unauthenticated scan-trigger and data API to the network.

---

## 1. Install the binary

```bash
VERSION=v0.6.10
SHA256=c8c5ecdc969e5e198c8c7ea557479589f27811c75fc1dca286584f696d63afc5

curl -fsSL -o /usr/local/bin/pqcscan \
  "https://github.com/orengacademy/pqc-scanner2/releases/download/${VERSION}/pqcscan-linux-x86_64"

echo "${SHA256}  /usr/local/bin/pqcscan" | sha256sum -c -    # must print: OK
chmod +x /usr/local/bin/pqcscan
pqcscan --help
```

`curl` and `sha256sum` use the system crypto libraries, so they work even on a
host whose Python lacks a working `ssl` module. Verify the checksum prints `OK`
**before** `chmod`. The Linux binary is built in a manylinux2014 container
(`scripts/build-linux-compat.sh`), so it needs only glibc ≥ 2.17: RHEL /
Oracle Linux 7.9, 8, and 9 all work. (Releases up to v0.6.9 were built on
`ubuntu-latest` and required glibc ≥ 2.38 — those fail on OL7 with
`GLIBC_2.38 not found`; use a newer release.)

Air-gapped host? Download the asset on a connected workstation, verify the
checksum, then `scp` it to `/usr/local/bin/pqcscan` on the target.

---

## 2. Install the systemd unit

Copy [`packaging/systemd/pqcscan.service`](../packaging/systemd/pqcscan.service)
to `/etc/systemd/system/pqcscan.service`, then:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now pqcscan
systemctl status pqcscan --no-pager
curl -fsS http://127.0.0.1:8765/api/health    # -> {"ok":true,"version":"..."}
```

The unit:

- runs the daemon bound to `127.0.0.1:8765`;
- stores the SQLite DB at `/var/lib/pqcscan/pqcscan.db` — systemd creates and
  owns `/var/lib/pqcscan` (`StateDirectory=`) before start;
- restarts on failure;
- is sandboxed (`ProtectSystem=strict`, `ProtectHome=read-only`,
  `NoNewPrivileges=true`, …) but deliberately keeps host **read** access and
  the `AF_INET`/`AF_INET6` socket families the network probes need.

### Privilege trade-off

`pqcscan` is a host crypto inventory scanner: it reads `/etc` configs
(`sshd_config`, `openssl.cnf`, nginx, apache), **private keys**
(`fs_cert_privkey`), and package DBs (`/var/lib/rpm`), and shells out to
`openssl`, `rpm`, `syft`, `nmap`, etc. Full coverage needs **root read**, which
is why the unit defaults to `User=root`.

To run least-privilege instead, edit the unit and replace:

```ini
User=root
Group=root
```

with:

```ini
DynamicUser=yes
```

Everything else (StateDirectory, sandbox) still works. Expect empty results for
root-owned `0600` material: `fs_cert_privkey`, sshd host keys, and any
root-only configs.

---

## 3. Reaching the UI

### Option A — SSH tunnel (simplest, no extra services)

```bash
ssh -L 8765:127.0.0.1:8765 user@your-host
# then open http://127.0.0.1:8765 in your local browser
```

### Option B — nginx reverse proxy with TLS + Basic auth

For shared / multi-user access. Terminates TLS and adds the auth the daemon
itself lacks. Keep the daemon on `127.0.0.1` (unit default).

```bash
# Create an auth user (RHEL/OL: httpd-tools provides htpasswd).
sudo dnf install -y httpd-tools
sudo htpasswd -c /etc/nginx/pqcscan.htpasswd pqcadmin
```

`/etc/nginx/conf.d/pqcscan.conf`:

```nginx
server {
    listen 443 ssl;
    server_name pqcscan.example.internal;

    ssl_certificate     /etc/pki/tls/certs/pqcscan.crt;
    ssl_certificate_key /etc/pki/tls/private/pqcscan.key;
    ssl_protocols       TLSv1.2 TLSv1.3;

    auth_basic           "pqcscan";
    auth_basic_user_file /etc/nginx/pqcscan.htpasswd;

    location / {
        proxy_pass         http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header   Host              $host;
        proxy_set_header   X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header   X-Forwarded-Proto $scheme;

        # Server-Sent Events (scan progress) must not be buffered.
        proxy_set_header   Connection "";
        proxy_buffering    off;
        proxy_read_timeout 1h;
    }
}

# Redirect plain HTTP to HTTPS.
server {
    listen 80;
    server_name pqcscan.example.internal;
    return 301 https://$host$request_uri;
}
```

```bash
sudo nginx -t && sudo systemctl reload nginx
# SELinux: allow nginx to make the upstream connection.
sudo setsebool -P httpd_can_network_connect 1
```

---

## 4. Troubleshooting (RHEL / Oracle Linux)

- **SELinux blocks exec.** If `systemctl status` shows a permission/exec denial
  for the binary in `/usr/local/bin`, relabel it and inspect the audit log:

  ```bash
  sudo restorecon -v /usr/local/bin/pqcscan
  sudo ausearch -m avc -ts recent
  ```

- **`pqcscan: command not found`** after install means the binary is not on the
  invoking shell's `PATH`, or the editable pip install never completed (broken
  Python `ssl`). Use the binary path in this guide; the unit calls it by
  absolute path so the service is unaffected.

- **DB location** is overridable with `--db <path>` in `ExecStart` or the
  `PQCSCAN_DB_PATH` environment variable. If you change it, update
  `ReadWritePaths=` accordingly.

---

## Configuration reference

| Setting    | Flag / env                         | Default                       |
| ---------- | ---------------------------------- | ----------------------------- |
| Bind addr  | `--bind`                           | `127.0.0.1`                   |
| Port       | `--port`                           | `8765`                        |
| DB path    | `--db` / `PQCSCAN_DB_PATH`         | `/var/lib/pqcscan/pqcscan.db` |

Health check endpoint: `GET /api/health` → `{"ok": true, "version": "..."}`.
