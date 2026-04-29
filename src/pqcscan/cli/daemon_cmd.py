from __future__ import annotations

from pathlib import Path

import click
import uvicorn

from pqcscan.daemon.app import create_app
from pqcscan.util.paths import default_db_path


@click.command()
@click.option("--port", type=int, default=8765)
@click.option("--bind", default="127.0.0.1", help="Bind address. Default 127.0.0.1.")
@click.option("--db", type=click.Path(path_type=Path), default=None)
def daemon_cmd(port: int, bind: str, db: Path | None) -> None:
    """Run the daemon (HTTP + SSE on 127.0.0.1)."""
    db_path = db or default_db_path()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    app = create_app(db_path=db_path)
    uvicorn.run(app, host=bind, port=port, log_level="info")
