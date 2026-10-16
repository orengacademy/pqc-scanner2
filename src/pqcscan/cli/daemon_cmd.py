from __future__ import annotations

import sys
from pathlib import Path

import click
import uvicorn

from pqcscan.daemon.app import create_app, is_loopback
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--port", type=int, default=8765)
@click.option("--bind", default="127.0.0.1", help="Bind address. Default 127.0.0.1.")
@click.option("--db", type=click.Path(path_type=Path), default=None)
@click.option("--tls-cert", type=click.Path(path_type=Path, exists=True), default=None,
              help="Serve HTTPS: PEM certificate (with --tls-key).")
@click.option("--tls-key", type=click.Path(path_type=Path, exists=True), default=None,
              help="Serve HTTPS: PEM private key (with --tls-cert).")
@click.option(
    "--token", default=None, envvar="PQCSCAN_TOKEN",
    help="Bearer/cookie token required on every request ($PQCSCAN_TOKEN). "
         "Mandatory when --bind is not a loopback address.",
)
def daemon_cmd(
    port: int, bind: str, db: Path | None, tls_cert: Path | None, tls_key: Path | None,
    token: str | None,
) -> None:
    """Run the daemon (HTTP + SSE on 127.0.0.1; HTTPS with --tls-cert/--tls-key)."""
    if bool(tls_cert) != bool(tls_key):
        click.echo("--tls-cert and --tls-key must be given together", err=True)
        sys.exit(2)
    if not is_loopback(bind) and not token:
        click.echo(
            f"refusing to bind {bind}: the daemon serves the host's crypto inventory. "
            "Pass --token (or set PQCSCAN_TOKEN), serve HTTPS with --tls-cert/--tls-key "
            "or a TLS reverse proxy, or keep --bind 127.0.0.1.",
            err=True,
        )
        sys.exit(2)
    db_path = db or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    app = create_app(db_path=db_path, token=token)
    uvicorn.run(
        app, host=bind, port=port, log_level="info",
        ssl_certfile=str(tls_cert) if tls_cert else None,
        ssl_keyfile=str(tls_key) if tls_key else None,
    )
