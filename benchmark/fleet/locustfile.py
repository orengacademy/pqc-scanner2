"""Locust user = one simulated agent host: enroll once, then POST one fresh bundle every LOAD_INTERVAL_S.

Env (set by run_load.py): LOAD_TEMPLATE (template bundle json), LOAD_PREFIX (machine-id prefix),
LOAD_ENROLL_TOKEN, LOAD_INTERVAL_S (default 60, the collector's per-host refill), LOAD_COUNTERS (output json),
LOAD_STAGGER (1: the first bundle goes out at a random offset in [0, interval), so offered load is steady at
hosts/interval; 0: every host posts as soon as it is spawned, a thundering herd).
Requests time out after 60 s, the real agent's HTTP timeout.
429 (throttled) and 503 (store busy) are expected collector answers: counted, not failures.
"""
import itertools
import json
import os
import random
import sys
from collections import Counter
from pathlib import Path

import gevent
from locust import HttpUser, constant, events, task

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _bundles import host_bundle

TEMPLATE = json.loads(Path(os.environ["LOAD_TEMPLATE"]).read_text())
PREFIX = os.environ.get("LOAD_PREFIX", "m-load-")
ENROLL_TOKEN = os.environ["LOAD_ENROLL_TOKEN"]
INTERVAL_S = float(os.environ.get("LOAD_INTERVAL_S", "60"))
STAGGER = os.environ.get("LOAD_STAGGER", "1") == "1"
COUNTERS: Counter = Counter()
_seq = itertools.count(1)   # locust users are greenlets in one process: no lock needed


@events.quitting.add_listener
def _write_counters(environment, **_kw):
    if path := os.environ.get("LOAD_COUNTERS"):
        Path(path).write_text(json.dumps(COUNTERS))


class FleetHost(HttpUser):
    wait_time = constant(INTERVAL_S)

    def on_start(self):
        n = next(_seq)
        self.machine_id, self.hostname = f"{PREFIX}{n:04d}", f"load-{n:04d}"
        self.labels = {"env": ("prod", "dr", "dev")[n % 3], "site": f"dc{n % 5}"}
        with self.client.post("/api/agents/enroll", name="enroll", catch_response=True, timeout=60, json={
                "enroll_token": ENROLL_TOKEN,
                "host": {"machine_id": self.machine_id, "hostname": self.hostname, "os": "linux",
                         "labels": self.labels, "agent_version": "load-test"}}) as r:
            if r.status_code == 201:
                self.token = r.json()["agent_token"]
            else:
                self.token = None
                r.failure(f"enroll {r.status_code}: {r.text[:120]}")
        if STAGGER:
            gevent.sleep(random.uniform(0, INTERVAL_S))

    @task
    def ingest(self):
        if not self.token:
            return
        body = host_bundle(TEMPLATE, self.machine_id, self.hostname, self.labels)
        with self.client.post("/api/ingest", name="ingest", data=body, catch_response=True, timeout=60, headers={
                "Authorization": f"Bearer {self.token}", "Content-Type": "application/gzip"}) as r:
            COUNTERS[f"http_{r.status_code}"] += 1
            if r.status_code in (200, 429, 503):
                r.success()
            else:
                r.failure(f"ingest {r.status_code}: {r.text[:120]}")
