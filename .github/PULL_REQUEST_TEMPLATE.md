# Summary

<!-- 1-3 bullet points: what changed and why. -->

# Linked issue(s)

<!-- "Closes #123" or "Refs #123". -->

# Type of change

- [ ] Bug fix
- [ ] New probe / framework / renderer
- [ ] Refactor (no behaviour change)
- [ ] Docs only
- [ ] CI / release plumbing
- [ ] Other:

# Test plan

<!-- A bulleted list of what you ran. At minimum:
- [ ] `pytest -q` passes locally
- [ ] `ruff check src/ tests/` clean
- [ ] `mypy src/pqcscan` clean
- [ ] If you added a probe: tested against synthetic fixtures + real config (where applicable)
- [ ] If you touched the OSV matcher: smoke-tested against `scripts/fetch-osv-snapshot.sh PyPI` output
-->

# Checklist

- [ ] I read [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- [ ] I added tests covering the new behaviour.
- [ ] I updated [`CHANGELOG.md`](../CHANGELOG.md) under `[Unreleased]` if
      this is a user-facing change.
- [ ] My commit messages follow the convention `<type>: <imperative
      summary>` (e.g. `feat:`, `fix:`, `docs:`, `chore:`, `refactor:`).
- [ ] CI is green.

# Additional notes

<!-- Anything reviewers should know: tradeoffs, follow-up issues to file,
     deliberate scope cuts. -->
