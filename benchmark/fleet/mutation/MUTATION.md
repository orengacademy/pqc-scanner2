# Mutation results: fleet collector and bundle loader

mutmut 3.8.0 mutated `src/pqcscan/daemon/fleet.py` and `src/pqcscan/store/bundle.py` at `8457f85` on a clean 8-vCPU
droplet and ran the nine fleet test files named in `pyproject.toml` `[tool.mutmut]` against each mutant (outputs
committed in `c8c31fc`; `README.md` has the setup). Neither source file has changed since `8457f85`, so the line
numbers below point at the current code.

## Score

| | Mutants |
|---|---|
| total | 447 |
| killed in the droplet run | 333 |
| survived in the droplet run | 113 |
| timeout in the droplet run | 1 |
| killed by the in-scope tests (24 survivors and the timeout) | 25 |
| killed by the two whole-object tests | 30 |
| equivalent | 14 |
| open: message text | 42 |
| open: other | 3 |

**Raw score of the droplet run: 333 / 447 = 0.745.**

**Adjusted score with the new tests: killed / (total - equivalent) = (333 + 25 + 30) / (447 - 14) = 388 / 433 = 0.896.**

The 60 targeted mutants were re-run with the new tests; the 333 already killed stay killed because no test was
removed. The 42 message-text mutants were not re-run, so the figure is a lower bound.

## How the kills were proven

Each kill was proven on this workstation, against the `mutants/` tree mutmut generates:

1. `mutmut run --max-children 1 <ids>` re-ran the selected tests for those mutants, in two rounds. For the 25
   in-scope ids `mutmut results` listed all 25 as `killed`. For the 35 `_host_dict` and `dump_bundle` ids it listed
   30 as `killed` and 5 as `survived` (`_host_dict #17`, `#21`, `dump_bundle #9`, `#91`, `#92`).
2. For the 25 in-scope ids, each killing test was also run on its own with `PYTHONPATH=mutants/src` and
   `MUTANT_UNDER_TEST=<id>` (mutmut 3.8's own mutant switch). It failed on the mutant and passed on the original through the same mutated module. As a control,
   the new tests pass on three mutants classed equivalent below (`_read_capped #6`, `load_bundle #13`, `_req_str #3`).

## Scope

Killed or justified: every survivor in agent auth, the token bucket, the request body cap (`_read_capped`), the
ingest queue and read bounds, the size caps and identity, findings and label checks in `load_bundle` (with its
helper `_req_str`) and `check_labels`, `resolve_ingest_parallelism`, and the `revoked` flag the fleet API reports.
No mutant of `enroll` (token compare, revoked host, labels) or of the `ingest` handler (read bounds, body timeout,
queue re-check) survived the droplet run.

Message-text mutants inside those functions are left open: they change only the error wording, while the status
code or exception class, which agents and callers act on, is pinned. Pinning every string would make the tests fail
on rewording.

Beyond that scope, two whole-object tests cover `_host_dict` (the `/api/fleet` host object) and `dump_bundle` (the
agent-side serializer): `test_fleet_api_host_object_is_complete` asserts every field of the host object in both
fleet responses, and `test_round_trip_keeps_the_whole_document` asserts the loaded bundle field by field, that the
raw JSON is compact, and that a bundle exactly at the raw cap still dumps. Together they kill 30 of those 35.

### Still open besides message text

| Mutant | Why it stays open |
|---|---|
| `dump_bundle #9` | `order_by(None)`: SQLite returns the rows in id order without `ORDER BY`, so no test on SQLite sees it; Postgres gives no such order, so it is not equivalent |
| `dump_bundle #91`, `#92` | compression level 9 or 7 instead of 6: the bundle inflates to the same bytes and only its wire size changes; a test would have to pin zlib's output bytes |

## Equivalent mutants

| Mutant | Why no test can tell it apart |
|---|---|
| `_read_capped #6`, `build_fleet_router #21` | Starlette request header lookup is case-insensitive |
| `_host_dict #17`, `#21` | `first_seen` and `last_seen` are NOT NULL columns, so `x.isoformat() if (x) or True else None` takes the same branch as the original |
| `build_fleet_router #52`, `#53`, `#74`, `#75` | Starlette lowercases response header names before sending |
| `build_fleet_router #22` | with no Authorization header, `""` and `"XXXX"` both fail the `bearer ` prefix check: 401 either way |
| `build_fleet_router #1` | `create_app`, the only caller, always passes `keep_scans_per_host`, so the default is never used |
| `load_bundle #13` | over the cap either read limit returns more than `MAX_RAW_BYTES` bytes and raises `BundleTooLarge`; at or under it both read the whole stream |
| `_req_str #3` | for a required field an absent key gives `""` instead of `None`; both fail the non-empty check with the same message |
| `dump_bundle #80`, `#83` | `default=str` is never reached: every dumped value is already JSON-native (JSON columns, `_iso` strings) |

## Every mutant that was not killed in the droplet run

Ids are shortened: `_read_capped #5` is `pqcscan.daemon.fleet.x__read_capped__mutmut_5`, `_TokenBucket.take #20` is
`pqcscan.daemon.fleet.xǁ_TokenBucketǁtake__mutmut_20`. `results.txt` lists the full ids; `survivors/` holds
`mutmut show` diffs for 71 of them (mutmut wrote no diff for the other 43, which were read from the generated
`mutants/` tree).

| Mutant | File:line | Mutation | Class | Verdict |
|---|---|---|---|---|
| `_TokenBucket.take #20` | fleet.py:74 | `> 0` becomes `> 1` | rate limit | killed by `test_token_bucket_refills_sub_second_intervals_and_denials_cost_nothing` |
| `_TokenBucket.take #27` | fleet.py:76 | `if ok` becomes `if (ok) or True` | rate limit | killed by `test_token_bucket_refills_sub_second_intervals_and_denials_cost_nothing` |
| `_read_capped #5` | fleet.py:84 | `"content-length"` becomes `"XXcontent-lengthXX"` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #6` | fleet.py:84 | `"content-length"` becomes `"CONTENT-LENGTH"` | header case | equivalent: Starlette request header lookup is case-insensitive |
| `_read_capped #7` | fleet.py:84 | `or 0` becomes `or 1` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #8` | fleet.py:86 | `= 0` becomes `= None` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #9` | fleet.py:86 | `= 0` becomes `= 1` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #10` | fleet.py:87 | `declared >` becomes `declared >=` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #12` | fleet.py:88 | `f"body over {cap} bytes"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `_read_capped #14` | fleet.py:88 | `f"body over {cap} bytes"` removed | message text | open: wording only; status code and exception type unchanged |
| `_read_capped #18` | fleet.py:90 | `= 0` becomes `= 1` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #19` | fleet.py:92 | `size +=` becomes `size =` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #21` | fleet.py:93 | `size >` becomes `size >=` | body cap | killed by `test_read_capped_bounds` |
| `_read_capped #23` | fleet.py:94 | `f"body over {cap} bytes"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `_read_capped #25` | fleet.py:94 | `f"body over {cap} bytes"` removed | message text | open: wording only; status code and exception type unchanged |
| `_host_dict #1` | fleet.py:100 | `{"host_id"` becomes `{"XXhost_idXX"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #2` | fleet.py:100 | `{"host_id"` becomes `{"HOST_ID"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #7` | fleet.py:100 | `"os"` becomes `"XXosXX"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #8` | fleet.py:100 | `"os"` becomes `"OS"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #12` | fleet.py:101 | `"agent_version"` becomes `"XXagent_versionXX"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #13` | fleet.py:101 | `"agent_version"` becomes `"AGENT_VERSION"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #14` | fleet.py:102 | `"first_seen"` becomes `"XXfirst_seenXX"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #15` | fleet.py:102 | `"first_seen"` becomes `"FIRST_SEEN"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #16` | fleet.py:102 | `if h.first_seen` becomes `if (h.first_seen) and False` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #17` | fleet.py:102 | `if h.first_seen` becomes `if (h.first_seen) or True` | response field | equivalent: `first_seen` and `last_seen` are NOT NULL columns, so the `else None` branch is never taken |
| `_host_dict #18` | fleet.py:103 | `"last_seen"` becomes `"XXlast_seenXX"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #19` | fleet.py:103 | `"last_seen"` becomes `"LAST_SEEN"` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #20` | fleet.py:103 | `if h.last_seen` becomes `if (h.last_seen) and False` | response field | killed by `test_fleet_api_host_object_is_complete` |
| `_host_dict #21` | fleet.py:103 | `if h.last_seen` becomes `if (h.last_seen) or True` | response field | equivalent: `first_seen` and `last_seen` are NOT NULL columns, so the `else None` branch is never taken |
| `_host_dict #24` | fleet.py:103 | `h.revoked` becomes `None` | revoked flag | killed by `test_revoked_token_is_401` |
| `resolve_ingest_parallelism #5` | fleet.py:110 | `if repo.engine.dialect.name == "postgresql"` becomes `if (repo.engine.dialect.name == "postgresql") and False` | parallelism | killed by `test_resolve_ingest_parallelism_picks_the_constant_by_dialect` |
| `resolve_ingest_parallelism #8` | fleet.py:110 | `== "postgresql"` becomes `== "XXpostgresqlXX"` | parallelism | killed by `test_resolve_ingest_parallelism_picks_the_constant_by_dialect` |
| `resolve_ingest_parallelism #9` | fleet.py:110 | `== "postgresql"` becomes `== "POSTGRESQL"` | parallelism | killed by `test_resolve_ingest_parallelism_picks_the_constant_by_dialect` |
| `build_fleet_router #1` | fleet.py:116 | `= 12` becomes `= 13` | retention default | equivalent: `create_app`, the only caller, always passes `keep_scans_per_host` |
| `build_fleet_router #6` | fleet.py:122 | `repo` becomes `None` | parallelism | killed by `test_resolve_ingest_parallelism_picks_the_constant_by_dialect` |
| `build_fleet_router #11` (was timeout) | fleet.py:123 | `= 0` becomes `= 1` | queue bound | killed by `test_one_place_ingest_queue_admits_a_bundle` |
| `build_fleet_router #21` | fleet.py:128 | `"authorization"` becomes `"AUTHORIZATION"` | header case | equivalent: Starlette request header lookup is case-insensitive |
| `build_fleet_router #22` | fleet.py:128 | `""` becomes `"XXXX"` | auth | equivalent: with no Authorization header, `""` and `"XXXX"` both fail the `bearer ` prefix check: 401 either way |
| `build_fleet_router #29` | fleet.py:130 | `"agent token required"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #31` | fleet.py:130 | `"agent token required"` removed | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #33` | fleet.py:130 | `"agent token required"` becomes `"XXagent token requiredXX"` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #34` | fleet.py:130 | `"agent token required"` becomes `"AGENT TOKEN REQUIRED"` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #43` | fleet.py:134 | `"store busy, retry later"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #46` | fleet.py:134 | `"store busy, retry later", headers={"Retry-After"` becomes `headers={"Retry-After"` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #49` | fleet.py:134 | `"store busy, retry later"` becomes `"XXstore busy, retry laterXX"` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #50` | fleet.py:134 | `"store busy, retry later"` becomes `"STORE BUSY, RETRY LATER"` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #52` | fleet.py:134 | `headers={"Retry-After"` becomes `headers={"retry-after"` | header case | equivalent: Starlette lowercases response header names before sending |
| `build_fleet_router #53` | fleet.py:134 | `headers={"Retry-After"` becomes `headers={"RETRY-AFTER"` | header case | equivalent: Starlette lowercases response header names before sending |
| `build_fleet_router #58` | fleet.py:136 | `"unknown or revoked agent token"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #60` | fleet.py:136 | `"unknown or revoked agent token"` removed | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #62` | fleet.py:136 | `"unknown or revoked agent token"` becomes `"XXunknown or revoked agent tokenXX"` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #63` | fleet.py:136 | `"unknown or revoked agent token"` becomes `"UNKNOWN OR REVOKED AGENT TOKEN"` | message text | open: wording only; status code and exception type unchanged |
| `build_fleet_router #74` | fleet.py:184 | `headers={"Retry-After"` becomes `headers={"retry-after"` | header case | equivalent: Starlette lowercases response header names before sending |
| `build_fleet_router #75` | fleet.py:184 | `headers={"Retry-After"` becomes `headers={"RETRY-AFTER"` | header case | equivalent: Starlette lowercases response header names before sending |
| `_req_str #3` | bundle.py:67 | `if nonempty` becomes `if (nonempty) and False` | identity check | equivalent: for a required field an absent key gives `""` instead of `None`; both fail the non-empty check with the same message |
| `_req_str #10` | bundle.py:67 | `""` becomes `"XXXX"` | identity default | killed by `test_load_accepts_minimal_valid_doc` |
| `_req_str #15` | bundle.py:69 | `f"{key} must be a {'non-empty ' if nonempty else ''}string"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `_req_str #16` | bundle.py:69 | `if nonempty` becomes `if (nonempty) and False` | message text | open: wording only; status code and exception type unchanged |
| `_req_str #17` | bundle.py:69 | `if nonempty` becomes `if (nonempty) or True` | message text | open: wording only; status code and exception type unchanged |
| `_req_str #18` | bundle.py:69 | `{'non-empty '` becomes `{'XXnon-empty XX'` | message text | open: wording only; status code and exception type unchanged |
| `_req_str #19` | bundle.py:69 | `{'non-empty` becomes `{'NON-EMPTY` | message text | open: wording only; status code and exception type unchanged |
| `_req_str #20` | bundle.py:69 | `else ''` becomes `else 'XXXX'` | message text | open: wording only; status code and exception type unchanged |
| `check_labels #4` | bundle.py:79 | `"host.labels values must be strings"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `check_labels #5` | bundle.py:79 | `"host.labels values must be strings"` becomes `"XXhost.labels values must be stringsXX"` | message text | open: wording only; status code and exception type unchanged |
| `check_labels #6` | bundle.py:79 | `"host.labels values must be strings"` becomes `"HOST.LABELS VALUES MUST BE STRINGS"` | message text | open: wording only; status code and exception type unchanged |
| `dump_bundle #4` | bundle.py:87 | `f"scan {scan_id} not found"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `dump_bundle #9` | bundle.py:91 | `FindingRow.id` becomes `None` | ordering | open: SQLite returns the rows in id order without `ORDER BY`, so no test on SQLite sees it; not equivalent on Postgres |
| `dump_bundle #32` | bundle.py:97 | `"remediation"` becomes `"XXremediationXX"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #33` | bundle.py:97 | `"remediation"` becomes `"REMEDIATION"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #34` | bundle.py:97 | `r.remediation or` becomes `r.remediation and` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #35` | bundle.py:97 | `"created_at"` becomes `"XXcreated_atXX"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #36` | bundle.py:97 | `"created_at"` becomes `"CREATED_AT"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #37` | bundle.py:97 | `r.created_at` becomes `None` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #59` | bundle.py:106 | `"started_at"` becomes `"XXstarted_atXX"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #60` | bundle.py:106 | `"started_at"` becomes `"STARTED_AT"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #61` | bundle.py:106 | `scan.started_at` becomes `None` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #62` | bundle.py:106 | `"finished_at"` becomes `"XXfinished_atXX"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #63` | bundle.py:106 | `"finished_at"` becomes `"FINISHED_AT"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #64` | bundle.py:106 | `scan.finished_at` becomes `None` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #72` | bundle.py:108 | `"tool_versions"` becomes `"XXtool_versionsXX"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #73` | bundle.py:108 | `"tool_versions"` becomes `"TOOL_VERSIONS"` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #74` | bundle.py:108 | `scan.tool_versions or` becomes `scan.tool_versions and` | serialization field | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #79` | bundle.py:112 | `separators=(",", ":")` becomes `separators=None` | encoding | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #80` | bundle.py:112 | `default=str` becomes `default=None` | encoding | equivalent: `default=str` is never reached; every dumped value is already JSON-native (JSON columns, `_iso` strings) |
| `dump_bundle #82` | bundle.py:112 | `separators=(",", ":"), default=str` becomes `default=str` | encoding | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #83` | bundle.py:112 | `default=str` removed | encoding | equivalent: `default=str` is never reached; every dumped value is already JSON-native (JSON columns, `_iso` strings) |
| `dump_bundle #86` | bundle.py:113 | `raw) >` becomes `raw) >=` | agent-side cap | killed by `test_round_trip_keeps_the_whole_document` |
| `dump_bundle #87` | bundle.py:114 | `BundleTooLarge(f"bundle is {len(raw)} bytes raw; cap {MAX_RAW_BYTES}"` becomes `BundleTooLarge(None` | message text | open: wording only; status code and exception type unchanged |
| `dump_bundle #91` | bundle.py:115 | `compresslevel=6` removed | encoding | open: the compression level changes only the wire size; pinning it would pin zlib's output bytes |
| `dump_bundle #92` | bundle.py:115 | `compresslevel=6` becomes `compresslevel=7` | encoding | open: the compression level changes only the wire size; pinning it would pin zlib's output bytes |
| `load_bundle #1` | bundle.py:119 | `data) >` becomes `data) >=` | size cap | killed by `test_load_size_caps_are_inclusive` |
| `load_bundle #2` | bundle.py:120 | `BundleTooLarge(f"bundle is {len(data)} bytes gzip; cap {MAX_GZIP_BYTES}"` becomes `BundleTooLarge(None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #6` | bundle.py:122 | `16` becomes `17` | gzip framing | killed by `test_load_rejects_zlib_framing` |
| `load_bundle #11` | bundle.py:124 | `MAX_RAW_BYTES + 1` removed | bomb memory | killed by `test_load_inflates_a_bomb_no_further_than_the_cap` |
| `load_bundle #12` | bundle.py:124 | `MAX_RAW_BYTES +` becomes `MAX_RAW_BYTES -` | size cap | killed by `test_load_size_caps_are_inclusive` |
| `load_bundle #13` | bundle.py:124 | `+ 1` becomes `+ 2` | size cap | equivalent: over the cap either read limit returns more than `MAX_RAW_BYTES` bytes and raises `BundleTooLarge`; at or under it both read the whole stream |
| `load_bundle #14` | bundle.py:126 | `f"bad gzip: {e}"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #15` | bundle.py:127 | `MAX_RAW_BYTES or` becomes `MAX_RAW_BYTES and` | size cap | killed by `test_load_size_caps_are_inclusive` |
| `load_bundle #16` | bundle.py:127 | `raw) >` becomes `raw) >=` | size cap | killed by `test_load_size_caps_are_inclusive` |
| `load_bundle #17` | bundle.py:128 | `f"bundle decompresses past {MAX_RAW_BYTES} bytes"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #20` | bundle.py:130 | `"bad gzip: truncated stream"` becomes `"XXbad gzip: truncated streamXX"` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #24` | bundle.py:134 | `f"bad json: {e}"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #31` | bundle.py:136 | `"unsupported or missing schema_version"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #32` | bundle.py:136 | `"unsupported or missing schema_version"` becomes `"XXunsupported or missing schema_versionXX"` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #33` | bundle.py:136 | `"unsupported or missing schema_version"` becomes `"UNSUPPORTED OR MISSING SCHEMA_VERSION"` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #52` | bundle.py:140 | `if findings is None` becomes `if (findings is None) and False` | findings default | killed by `test_load_defaults_absent_findings_to_empty` |
| `load_bundle #63` | bundle.py:144 | `"host, host.labels and scan must be objects and findings a list"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #64` | bundle.py:144 | `"host, host.labels and scan must be objects and findings a list"` becomes `"XXhost, host.labels and scan must be objects and findings a listXX"` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #65` | bundle.py:144 | `"host, host.labels and scan must be objects and findings a list"` becomes `"HOST, HOST.LABELS AND SCAN MUST BE OBJECTS AND FINDINGS A LIST"` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #66` | bundle.py:145 | `findings) >` becomes `findings) >=` | size cap | killed by `test_load_size_caps_are_inclusive` |
| `load_bundle #67` | bundle.py:146 | `BundleTooLarge(f"bundle has {len(findings)} findings; cap {MAX_FINDINGS}"` becomes `BundleTooLarge(None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #70` | bundle.py:148 | `"every finding must be an object"` becomes `None` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #71` | bundle.py:148 | `"every finding must be an object"` becomes `"XXevery finding must be an objectXX"` | message text | open: wording only; status code and exception type unchanged |
| `load_bundle #72` | bundle.py:148 | `"every finding must be an object"` becomes `"EVERY FINDING MUST BE AN OBJECT"` | message text | open: wording only; status code and exception type unchanged |

## Re-check one mutant

```bash
.venv/bin/mutmut run --max-children 1 <full mutant id>
.venv/bin/mutmut results --all true | grep <full mutant id>
```

mutmut regenerates `mutants/` and runs its stats pass over the nine test files before the mutant. Delete `mutants/`
afterwards; it is gitignored.
