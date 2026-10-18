# Fleet web UI at 500 hosts: browser review

Branch `verify/fleet-capacity`, 2026-10-18, measured against `a716747` plus the fixes listed below. This page closes the UI half of finding F13 in
[FLEET-EVIDENCE.md](FLEET-EVIDENCE.md): nobody had opened `/fleet` or timed a fleet export with hundreds of hosts. It records real-browser timings,
the design and accessibility findings from five review skills, and which defects were fixed. The hard rule was no new features, so only defects
were fixed, each in its own commit; polish stays open with the skill's suggestion.

**Verdict.** The pages work at 500 hosts, and 14 defects were fixed (8 high), five of them in a second round that caught regressions
from the first. Two slow paths stay open. `/fleet` takes about 2.2 s to first byte
and sends 532 KB of uncompressed HTML. The fleet CBOM export takes about 17 minutes and produces 343 MB.

## Setup

- **Data.** `python -m benchmark.fleet.make_fleet_db --hosts 500 --scans-per-host 2 --findings 1670 --out fleet.db` ingests 1,000 bundles
  through the daemon's own `Repo` (the load-test template from `benchmark/fleet/_bundles.py`). Hosts are `soak-0000` to `soak-0499`, labelled
  `env` (prod, dr, dev) and `site` (dc0 to dc4). The last bundle of every 10th host renames one finding, so 50 hosts show `drift 2`. The rename
  changes the title and the evidence path, because drift keys on the path when a finding has one; a title change alone gives zero drift. The DB is
  1.08 GB. One host (`soak-0002`) was backdated 5 days by hand in the scratch DB to show the stale marker. In the second round one scanless
  host (`aaa-noscan`) was enrolled there to show the readiness placeholder, so the after-fix Lighthouse runs saw 501 hosts.
- **Build time.** 310.7 s for 500 hosts, against the brief's 3-minute target, at load average 24.5. Ingest costs about 0.33 s per 1,670-finding
  bundle on this box (profiled: `Repo.ingest_bundle` plus the template build); the target needs an idle machine or a bypass of the product's
  ingest path, which would defeat the point.
- **Daemon.** `pqcscan daemon --db fleet.db --bind 127.0.0.1 --port 44193`, loopback, no token.
- **Browser.** Chrome DevTools MCP in an isolated context: `new_page`, `navigate_page`, `resize_page`, `emulate` (viewport and colour scheme),
  `take_screenshot`, `take_snapshot`, `evaluate_script` (Navigation Timing and layout probes), `performance_start_trace`/`performance_stop_trace`,
  `lighthouse_audit`, `list_console_messages`. It worked first time, so Playwright MCP was not used.

**Timings are relative, not absolute.** The workstation is shared and was loaded throughout (load average 17 to 25, noted per row). Each page
load ran three times; the table shows the median. Raw runs are in `benchmark/fleet/ui/timings.json`.

## Timings at 500 hosts

| Page | TTFB | DOMContentLoaded | Load | Transfer | Trace LCP | Load avg |
|---|---|---|---|---|---|---|
| `/fleet` | 2,201 ms | 2,743 ms | 2,759 ms | 532,585 B | 3,774 / 2,392 ms | 19.9 to 21.1 |
| `/fleet?label=env=prod` (167 hosts) | 2,147 ms | 2,310 ms | 2,317 ms | 182,861 B | 4,915 ms | 21.1 |
| `/fleet/1` | 26 ms | 124 ms | 124 ms | 8,495 B | 256 ms | 21.1 |

Curl gives the same picture: `/fleet` total 2.29 s median, the filtered page 1.79 s, the host page 0.022 s. The filter is applied after
`fleet_summary()` reads every host, so it saves transfer but not server time. The trace's DocumentLatency insight puts the saving from text
compression at 357 KB on `/fleet`. DOMSize flags 6,116 nodes.

| Export (F13) | Result | Time | Size | Load avg |
|---|---|---|---|---|
| `GET /api/scans/fleet/export/json` | 400 `unknown format: json` | 3 ms | 33 B | 17.3 |
| `GET /api/fleet` (the JSON fleet summary) | 200 | 2.36 s median of 3 | 176,841 B | 25.3 |
| `GET /api/scans/fleet/export/cbom` | 200 | **1,005.6 s** (one run) | **342,909,425 B** | 17.3 at start |

There is no `json` export format; the formats are cbom, sarif, pdf-tech, pdf-exec, xlsx-bukukerja and xlsx-generic. The CBOM export ran once.
Each run holds the daemon's render slot for about 17 minutes, so the second run was cancelled by restarting the daemon, and the third never
started. While it ran, the daemon process held the GIL in one thread, so no page timing above was taken during an export.

Lighthouse (`lighthouse_audit` covers accessibility, best practices and SEO; performance comes from the trace):

| Page | Before (a11y / BP / SEO) | After all fixes (a11y / BP / SEO) |
|---|---|---|
| `/fleet`, light, mobile snapshot | 95 / 100 / 75 | 100 / 100 / 75 |
| `/fleet`, dark, desktop | 95 / 100 / 75 (snapshot) | 100 / 100 / 90 (navigation) |
| `/fleet?label=env=prod`, dark, navigation | 95 / 100 / 90 | 100 / 100 / 90 |
| `/fleet/1`, dark, navigation | 95 / 100 / 90 | 100 / 100 / 90 |

The after column was re-audited on 2026-10-19 at `23674f1`; both columns are in `timings.json`.

The remaining failure is `meta-description`, which does not apply to a local admin tool. Snapshot mode scores SEO lower than navigation mode
on the same page.

## Skills used

| Skill | What it returned |
|---|---|
| `interfaces:interface-review` | Not invocable: it is user-only (`disable-model-invocation`). `interfaces:better-interface`, its screen-review orchestrator, ran instead and routed to the six domain skills below. |
| `interfaces:better-interface` | Scope and severity rules; escalation triggers made U1, U2, U3, U4 and U5 high on sight. |
| `interfaces:better-accessibility` | U1 (reflow at 320 px), U3 and U4 (contrast), U5 (error without recovery), U9 (cells without headers), U13 (no skip link), U14 (page title). |
| `interfaces:better-layout` | U1, U2, U8 (static marker styled as a control), P4 (headers scroll away). |
| `interfaces:better-writing` | U5, U6 (misleading empty state), P1, P2, P3, P10. |
| `interfaces:better-typography` | P6 (14 px input zooms on iOS); confirmed the hostname wrapping fixed in `ed6dd85`. |
| `interfaces:better-colors` | Measured pairs for U3 and U4; drift moved to a neutral pill because blue means "link" on this page. The skill says to report failing pairs and leave colours alone; the brief classes unreadable contrast as a defect to fix, so they were fixed. |
| `interfaces:better-ui` | P11 (theme switch smears); `transition: all` on the old chip (gone from fleet pages after U8). |
| `impeccable:impeccable` | Critique mode, run single-context (degraded: the task forbids subagents, and the skill's dual-agent mode needs them). Nielsen score 18/40. Detector CLI on both templates: 0 findings. Browser overlay on the filter page: `low-contrast` 2.9:1 on the active nav (U3), `dark-glow` on the brand dot (P8), `kicker-above-heading` (P7), `cramped-padding` on the table card (false positive: the cells carry their own padding). Questions skipped: findings go to this document. |
| `taste-skill:taste-skill` | Declares dashboards and data tables out of scope (its section 13). Applicable rules gave P7 (eyebrow restraint), P8 (no glows) and P9 (em-dash null placeholder). |
| `ui-ux-pro-max:ui-ux-pro-max` | UX rules "Table Handling: overflow-x-auto wrapper" (U1) and "Avoid horizontal scrolling" (U2); `virtualize-lists` for 500 rows (P5). |

## Findings

Severity is **defect** (broken, unreadable, inaccessible, misleading or slow) with H/M/L impact, or **polish**. Before and after screenshots
are in `benchmark/fleet/ui/`.

| # | Page | Element | Problem | Evidence | Severity | Raised by | Fixed in |
|---|---|---|---|---|---|---|---|
| U1 | `/fleet`, `/fleet/1` | Table card | `overflow-hidden` clipped every column after Last seen at 390 px: readiness, counts and scan links unreachable. Once U2 was fixed the table shrank instead and broke hostnames (`soak-`/`0000`) | `fleet-500-mobile.png` → `after-table-scroll-mobile.png`, `final-fleet-500-mobile.png` | Defect H (unreachable) | better-accessibility, better-layout, ui-ux-pro-max | `e28e162`, `ed6dd85` |
| U2 | All pages | Header nav | The 716 px nav row could not shrink, so the layout viewport grew to 822 px and every page scrolled sideways on a phone | `fleet-500-mobile.png` (innerWidth 822) → `after-nav-mobile.png` (390) | Defect H (broken) | better-layout, ui-ux-pro-max | `fd59b85` |
| U3 | Fleet pages, light theme | Links, accent, readiness numbers, done pill | No light remap for blue/red/emerald text or pills: links 2.54:1, amber accent 2.75 to 3.15:1 (token comment said "readable on white"), done pill 1.27:1 | Lighthouse `color-contrast`; impeccable `low-contrast`; `fleet-500-desktop.png`, `fleet-host.png` → `after-contrast-light.png` | Defect H (unreadable) | better-accessibility, better-colors, impeccable | `6ca63b2` |
| U4 | Fleet pages, dark theme | zinc-500 small text | Eyebrow, labels, headers, last-seen column at 4.11:1 on the page, 3.86:1 on cards; 513 nodes on `/fleet` | Lighthouse `color-contrast`; `fleet-500-desktop-dark.png` → `after-contrast-dark.png` | Defect H (unreadable) | better-colors | `9fd4f9f` |
| U5 | `/fleet?label=env` | Label filter | Malformed filter answered with a bare JSON body: no page, no field, no way back | `before-filter-malformed.png` → `after-filter-malformed.png` | Defect H (no recovery) | better-writing, better-accessibility | `29e3040` |
| U6 | `/fleet?label=env=prd` | Empty state | A filter that matches nothing said "No enrolled hosts yet. Run pqcscan scan --report-to on a host." on a 500-host fleet | `before-filter-nomatch.png` → `after-filter-nomatch.png` | Defect H (misleading) | better-writing | `79fa9d2` |
| U7 | `/fleet`, `/fleet/1` | Last seen, Started | Naive UTC printed with microseconds and no zone; reads 8 hours off on this UTC+8 box; a never-seen host would print `None` | `fleet-host.png` → `after-timestamps-host.png` | Defect M (misleading) | better-interface review, impeccable (heuristic 2) | `f010107` |
| U8 | `/fleet`, `/fleet/1` | Stale and drift markers | Used the clickable filter chip (pointer cursor, button padding, hover transition) on a static span; stretched rows from 41 to 59 px; wrapped on phones | `fleet-500-desktop.png`, `fleet-500-mobile.png` → `after-pills-desktop-dark.png` | Defect M (misleading) | better-layout, better-colors, better-ui | `a9b0fe4` |
| U9 | `/fleet`, filter, `/fleet/1` | Last column header | Empty `<th>`, so the scan-link cells had no header | Lighthouse `td-has-header` → passes | Defect M (inaccessible) | better-accessibility | `c626b3c` |
| U10 | `/fleet` | Whole page | 2.2 s to first byte, 532 KB uncompressed HTML, 6,116 DOM nodes at 500 hosts; the label filter runs after the full summary | `timings.json`; trace DocumentLatency, DOMSize | Defect H (slow) | Chrome trace, ui-ux-pro-max | Open |
| U11 | Fleet CBOM export | `/api/scans/fleet/export/cbom` | 1,005.6 s and 343 MB at 500 hosts; holds the render slot throughout | `timings.json` (curl) | Defect H (slow) | curl (F13) | Open |
| U12 | Fleet JSON export | `/api/scans/fleet/export/json` | Does not exist (400). The brief and F13 name it; `/api/fleet` is the JSON fleet surface | `timings.json` | Note (docs) | curl | Open |
| U13 | All pages | Body start | No skip link: keyboard users tab through 12 header controls before the content on every page. Not a defect: the `<main>` landmark and `<h1>` let screen-reader users jump, which meets WCAG 2.4.1 | Snapshot of `/fleet/1` | Polish | better-accessibility | Open |
| U14 | All pages | `<title>` | Every page is titled `pqcscan`; tabs and history entries are indistinguishable | Snapshot root `RootWebArea "pqcscan"` | Defect M (inaccessible) | better-accessibility | Open |
| U15 | Scan pages, light theme | `.sev-pill` crit/high/low/info | Same root cause as U3 (no light remap); only the `med` pill used on fleet pages was remapped | `app.css` | Defect M (unreadable), outside the fleet scope | better-colors | Open |
| U16 | Dashboard, scan detail, light theme | `.btn-primary` | Regression from `6ca63b2`: the darker `--accent` is the button background under zinc-900 text, 3.53:1 at rest and 2.50:1 on hover (were 5.56 / 3.53). White text gives 5.02 / 7.09 | `before-btn-primary-light.png` → `after-btn-primary-light.png`, `after-btn-primary-scan-light.png` | Defect H (unreadable) | Task review | `128bb14` |
| U17 | `/fleet?label=` at 390 px | Show all hosts link | Regression from `79fa9d2`/`29e3040` with `ed6dd85`: the empty-state cell spanned a nowrap table 727 to 1,029 px wide, so the link sat at x 329 to 447 past the card edge at 366 | `before-recovery-link-mobile.png` → `after-recovery-link-malformed-mobile.png`, `after-recovery-link-nomatch-mobile.png` | Defect H (unreachable) | Task review | `41ffedb` |
| U18 | Dashboard, scan diff, framework detail, risk assessment, dark | Muted links and close buttons | Regression from `9fd4f9f`: the theme-guarded zinc-500 rule, specificity (0,3,0), beat `hover:text-zinc-*` (0,2,0) on six elements, so they no longer lightened on hover | Hover on `/frameworks/qramm`: rgb(212,212,216) after | Defect M (broken hover state) | Task review | `8754a56` |
| U19 | `/fleet?label=env` | Host count | The malformed-filter page still said "0 Host" for a filter that never ran | `after-recovery-link-malformed-mobile.png` → `after-malformed-no-count-mobile.png` | Defect M (misleading) | Task review | `a9790b6` |
| U20 | `/fleet` | Readiness placeholder | The dash for a host with no scan was zinc-600: 2.57:1 dark, 3.34:1 light. Now 4.91 / 4.83 | `before-readiness-dash-dark.png` → `after-readiness-dash-dark.png` | Defect M (unreadable) | Task review | `23674f1` |
| P1 | `/fleet` | Host count | "500 Host": count glued to the singular column label | `final-fleet-500-desktop.png` | Polish | better-writing | Open |
| P2 | `/fleet/1` | Host details | `machine id:`, `os:`, `agent:` hard-coded English and lower case beside translated `Labels:` | `fleet-host.png` | Polish | better-writing | Open |
| P3 | `/fleet?label=` | Filtered count | "167 Host" gives no "of 500" and no way to clear the filter while matches exist | `fleet-filter.png` | Polish | better-writing, impeccable (heuristic 3) | Open |
| P4 | `/fleet` | Table header | Column headers scroll away across 500 rows of bare numbers | `fleet-500-desktop.png` | Polish | better-layout, impeccable (heuristic 6) | Open |
| P5 | `/fleet` | Table | No sort or paging for 500 rows | trace DOMSize | Polish (a feature) | impeccable (heuristic 7), ui-ux-pro-max | Open |
| P6 | `/fleet` | Filter input | 14 px input zooms the page on iOS Safari | `fleet.html` input `text-sm` | Polish | better-typography | Open |
| P7 | `/fleet` | Eyebrow | "FLEET" kicker above the "Fleet" heading says the same word twice | impeccable `kicker-above-heading` | Polish | impeccable, taste-skill | Open |
| P8 | All pages | Brand dot | Zero-offset amber glow | impeccable `dark-glow` | Polish | impeccable, taste-skill | Open |
| P9 | Fleet pages | Null placeholders | Em dash for missing readiness, labels, agent | `fleet.html`, `fleet_host.html` | Polish | taste-skill | Open |
| P10 | `/fleet`, `/fleet/1` | Scan links | "#2 →" and repeated "View →" do not name their destination out of context | Snapshot of `/fleet/1` | Polish | better-writing | Open |
| P11 | All pages | Theme toggle | Colour transitions on chrome run during the theme swap and smear it | `base.html` `transition-colors` | Polish | better-ui | Open |
| P12 | All pages at 390 px | Theme toggle, EN/MS | Since `fd59b85` the nav scrolls; the toggle (x 741) and locale buttons (x 766, 801) are off-screen until the nav is scrolled. The cut-off nav item is the only cue | `after-nav-mobile.png`, `final-fleet-500-mobile.png` | Polish | Task review | Open |

Not findings: Lighthouse `meta-description` (a local admin tool has no search listing), impeccable `cramped-padding` on the card (false
positive), and readiness 0 with critical 0 on every host. The last is the harness template, whose weak findings are all severity high, not the UI.

Counts: 18 defects (10 high, 8 medium), 1 docs note and 13 polish items. 14 defects are fixed (8 high, 6 medium) and 4 are open (2 high,
2 medium). The note and all polish items are open. U13 moved from defect to polish in the second round, and U16 to U20 came from the task
review of the first round: three of them were regressions introduced by first-round fixes.

## Open items with proposed fixes

- **U10, `/fleet` is slow.** Compress responses with Starlette's `GZipMiddleware`, excluding the export and ingest paths, then remeasure. Apply
  the label filter in SQL before the tally. Both touch the daemon beyond the fleet templates. Paging is a feature and was out of scope.
- **U11, fleet CBOM export.** `Repo.materialize_fleet_rollup` copies 835,000 findings and their views as ORM objects, host by host. Copy them
  with `INSERT ... SELECT` for findings and views, then stream the CBOM rather than building a 343 MB string. That is store and renderer work
  past the 40-line limit, so it stays open.
- **U12.** Correct the brief and F13 to name `/api/fleet` or a real export format.
- **U14, and polish U13.** In `base.html`, add `{% block title %}` per page and make a skip link the first focusable element. Neither is a
  fleet template, and both change every page, so they stay open.
- **U15.** Give the remaining `.sev-pill` colours light remaps, using the pattern from `6ca63b2`.

## Reproduce

```bash
.venv/bin/python -m benchmark.fleet.make_fleet_db --hosts 500 --scans-per-host 2 --findings 1670 --out /tmp/fleet.db
.venv/bin/pqcscan daemon --db /tmp/fleet.db --bind 127.0.0.1 --port 44193 &
curl -s -o /dev/null -w '%{time_starttransfer} %{time_total} %{size_download}\n' http://127.0.0.1:44193/fleet
curl -s -o /dev/null -w '%{time_total} %{size_download}\n' http://127.0.0.1:44193/api/scans/fleet/export/cbom   # about 17 min
.venv/bin/pytest -q tests/integration/test_ui_fleet.py
.venv/bin/pytest -q -m benchmark tests/benchmark/test_make_fleet_db.py
```
