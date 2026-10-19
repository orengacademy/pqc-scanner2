# Evidence page

`index.html` is the fleet capacity campaign's evidence summary as one self-contained page: the six spec item verdicts,
the tag decision, capacity per backend, the before and after profiles, the real soak's day counter per host, fuzz and
mutation results, the CI load-ratio baseline, web UI timings and the findings list. Every number row has a source cell
naming the file it came from. Inputs that do not exist yet show as pending.

Do not edit it by hand. Regenerate it from the committed artefacts:

```bash
python -m benchmark.fleet.evidence_page        # writes docs/evidence/index.html
```

The generator is `benchmark/fleet/evidence_page.py` (data: `load()`, page: `render()`), the markup and CSS are in
`benchmark/fleet/evidence_page.html.j2`, and `tests/benchmark/test_evidence_page.py` covers it. To view it, open the file
or serve the folder: `python -m http.server 8000 -d docs/evidence`. Fonts load from Google Fonts and fall back to the
system face offline; there is no JavaScript. Screenshots: `benchmark/fleet/ui/evidence-desktop.png`, `evidence-mobile.png`.
