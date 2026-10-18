"""Write the seed corpora: three valid bundle documents as JSON text (seeds/json/) and gzipped (seeds/raw/).

    python seed.py [outdir]        # default: seeds/ next to this file

The documents come from the load harness's own `build_template`, so they are what a real agent posts: one with host
labels, one with framework views and no labels, one whose scan failed.
"""
import copy
import gzip
import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[2]))


def documents() -> dict[str, dict]:
    from benchmark.fleet._bundles import build_template

    with tempfile.TemporaryDirectory() as tmp:
        base = build_template(Path(tmp), n_findings=3)
    base["host"] = {**base["host"], "machine_id": "seed-host", "hostname": "seed", "agent_version": "0.10.2"}
    labelled = copy.deepcopy(base)
    labelled["host"]["labels"] = {"env": "prod", "site": "kl", "owner": "platform"}
    viewed = copy.deepcopy(base)                 # build_template findings carry compliance views; assert it stays so
    assert any(f["views"] for f in viewed["findings"])
    failed = copy.deepcopy(base)
    failed["scan"] = {**failed["scan"], "status": "failed", "finished_at": None}
    failed["findings"] = []
    return {"labels": labelled, "views": viewed, "failed": failed}


def main(out: Path) -> None:
    for sub in ("json", "raw"):
        (out / sub).mkdir(parents=True, exist_ok=True)
    for name, doc in documents().items():
        text = json.dumps(doc, separators=(",", ":")).encode()
        (out / "json" / f"{name}.json").write_bytes(text)
        (out / "raw" / f"{name}.json.gz").write_bytes(gzip.compress(text, compresslevel=6))


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else HERE / "seeds")
