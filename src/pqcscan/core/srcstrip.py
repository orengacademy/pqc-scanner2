"""Language-aware comment/string blanking for regex-based source probes.

The non-Python source-code probes (``code.ts.go`` / ``.java`` (also Kotlin and
Scala) / ``.javascript`` / ``.php`` / ``.rust`` / ``.csharp``), and
``code.crypto_primitives`` (which adds Python and TypeScript through
:func:`noncode_spans`; C/C++, Ruby and Swift are left unstripped), detect weak crypto with plain regexes over raw source
text.  A weak-crypto token that appears inside a ``// comment`` or a
``"string literal"`` is a false positive.  This module neutralises those
regions *before* the detection regexes run, without any native grammar (so the
self-contained any-OS binary stays intact).

Design: for each language a single combined regex alternates over every lexical
form that must be ignored — block comments, line comments and each flavour of
string / char literal.  We ``finditer`` that combined pattern once, left to
right, and blank every matched span.  Because ``finditer`` returns
non-overlapping, left-most matches and resumes *after* each match, a ``//``
that lives inside a string is consumed by the string alternative first and is
therefore never re-interpreted as a comment — the "a ``//`` inside a string is
not a comment" precedence falls out of the scan order for free.  Likewise a
``"`` inside a ``// comment`` is swallowed by the line-comment match.

Blanking replaces every character of a matched span with a space (``" "``)
*except* newlines, which are preserved.  The result is therefore the exact same
length as the input and has identical newline positions, so downstream offset
maths (``text[:m.start()].count("\\n") + 1``) stays valid.

Probes do NOT run their detection regexes over the blanked text: several of
those regexes intentionally key off a string-literal *argument* (e.g.
``createHash('md5')`` or ``getInstance("MD5")``), whose algorithm name would be
blanked and thus lost.  Instead they match over the original ``text`` via
:func:`code_finditer`, which uses the blanked ``scan_text`` purely as a *mask*:
a match is kept only when its start offset (the call/identifier that anchors it)
is real code rather than the interior of a comment or string.  Recall is thus
preserved exactly; only anchors buried in comments/strings are dropped.

The function is fail-open: on any internal error it returns the original source
untouched, so detection recall can never regress — only false positives drop.

Known best-effort limitations (documented, acceptable for a regex MVP):
- Rust nested ``/* /* */ */`` block comments are treated as non-nested (the
  first ``*/`` closes the comment).
- Rust raw strings ``r"..."`` / ``r#"..."#`` / ``br"..."`` are matched
  best-effort via a hash-count backreference.
- JavaScript template-literal ``${ ... }`` interpolations and Kotlin / Scala
  ``$name`` / ``${ ... }`` string templates are blanked wholesale (the embedded
  expression is treated as string content, so a call inside one is missed).
- C# verbatim strings ``@"..."`` are handled; interpolated ``$"{...}"`` holes are
  blanked as string content like the templates above.
- An unterminated string or comment is left as code (not blanked) from its
  opener to the end of its line (quotes) or of the input (block comments, raw /
  verbatim strings).
- PHP heredoc/nowdoc (``<<<EOT``) bodies are not stripped.
- Multi-char Rust/Go char escapes such as ``'\\u{1F600}'`` are not matched.
"""
from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from functools import cache
from pathlib import Path

from pqcscan.core.types import Classification, Finding, Severity

# --- Lexical building blocks -------------------------------------------------
# Double-quoted string with backslash escapes, confined to a single line.
_DQ = r'"(?:\\.|[^"\\\n])*+"'
# Single-quoted *string* (JS / PHP): multi-character, backslash escapes.
_SQ_STR = r"'(?:\\.|[^'\\\n])*+'"

# Unterminated forms. Each follows the form it backs up and consumes what that
# form scanned and then rejected: an unterminated quote to the end of its line,
# an unterminated block comment / verbatim string / text block to the end of
# input.
# They are NOT blanked (fail-open: the text stays code). Without them finditer
# retried at every later opener and rescanned the same span — quadratic, e.g.
# 10 s for one 40 k-character line of \" escapes. The group names must start
# with "unterm" (strip_noncode skips blanking on them).
_DQ_UNTERM = r'(?P<unterm_dq>"(?:\\.|[^"\\\n])*+)'
_SQ_UNTERM = r"(?P<unterm_sq>'(?:\\.|[^'\\\n])*+)"
_BLOCK_UNTERM = r"(?P<unterm_block>/\*[\s\S]*)"
_CSHARP_VERBATIM_UNTERM = r'(?P<unterm_verbatim>@"[\s\S]*)'
# Single char / rune literal (Go / Java / Rust): exactly one char or one escape.
# Matching only a single element keeps Rust lifetimes (``&'a T``) safe.
_CHAR = r"'(?:\\.|[^'\\\n])'"
# Block comment (non-nested).  ``[\s\S]`` spans newlines without a global flag.
_BLOCK = r"/\*[\s\S]*?\*/"
# Line comments.
_LINE_SLASH = r"//[^\n]*"
_LINE_HASH = r"#[^\n]*"
# Backtick span: Go raw string literal and JS template literal.
_BACKTICK = r"`[^`]*`"
# Rust raw string opener: r"...", r#"..."#, br"..."#. The closer depends on the
# opener's hash count, so _blank_spans finds it in code (not a backreference),
# using a one-pass index of closers — see _raw_last_close.
_RUST_RAW_OPEN = r'(?P<raw_open>b?r(?P<rrhash>#*)")'
# C# verbatim string: @"..." where an embedded quote is written "". Spans
# newlines, so it must precede _DQ in the alternation (matched at the '@').
_CSHARP_VERBATIM = r'@"(?:""|[^"])*"'
# Triple-quoted forms span newlines and must precede _DQ, which would otherwise
# match the leading "" as an empty string and leave the body as code. A form
# that closes too early hands the rest of the string to the scanner as code,
# and one that closes too late hides real code after it (an evasion), so each
# follows its language's rule exactly:
# - Java 15+ text block: the opening """ must be followed by a line terminator;
#   backslash escapes (incl. \""") never close; it closes on the final run of
#   quotes, so a body ending in " is still inside.
# - Kotlin / Scala raw string: no escapes; also closes on the final quote run
#   ("""x"""" holds x").
# The body alternatives are disjoint (a quote is body only when it does not
# start a """ run) and possessive (*+), so the body never backtracks, and it
# cannot run past a """ — so an unterminated block only scans to the end of
# input once, with no later opener left to rescan. The closer is "*""" — the
# run of quotes the body refused, however long.
_JAVA_TEXT_BLOCK = r'"""[ \t\f]*\r?\n(?:[^"\\]|\\[\s\S]|"(?!""))*+"*"""'
_RAW_TRIPLE = r'"""(?:[^"]|"(?!""))*+"*"""'
# Their end-of-input partners. Without them a later opener *inside* the failed
# body (e.g. the """ of an escaped \""") rescanned to the end again: 17 s for
# 64 KiB. A body that reached the end of input never met a closer, and a later
# opener's body starts on the same token boundary (after a line break no escape
# can own), so no later block can close either: the form is dropped.
_JAVA_TEXT_BLOCK_UNTERM = r'(?P<unterm_tb>"""[ \t\f]*\r?\n[\s\S]*)'
_RAW_TRIPLE_UNTERM = r'(?P<unterm_rawtriple>"""[\s\S]*)'
# Python triple-quoted strings: escapes honoured, close on the FIRST unescaped
# run of three (""""x"""" holds "x, then a stray quote). Same disjoint possessive
# body; the end-of-input partner is safe to drop for the same reason as above.
_PY_TRIPLE_DQ = r'"""(?:[^"\\]|\\[\s\S]|"(?!""))*+"""'
_PY_TRIPLE_SQ = r"'''(?:[^'\\]|\\[\s\S]|'(?!''))*+'''"
_PY_TRIPLE_DQ_UNTERM = r'(?P<unterm_pydq>"""[\s\S]*)'
_PY_TRIPLE_SQ_UNTERM = r"(?P<unterm_pysq>'''[\s\S]*)"

# Per-language alternation members.  Order matters only where two forms can
# start at the same character: triple-quoted / verbatim forms precede _DQ, and
# each *_UNTERM form directly follows the form it backs up.  With those, every
# character is scanned a bounded number of times, so stripping is linear in the
# input length (pinned by timing tests in tests/unit/test_srcstrip.py).
_LANG_FORMS: dict[str, tuple[str, ...]] = {
    "go": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _BACKTICK, _DQ, _DQ_UNTERM, _CHAR),
    "java": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _JAVA_TEXT_BLOCK, _JAVA_TEXT_BLOCK_UNTERM, _DQ, _DQ_UNTERM, _CHAR),
    "kotlin": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _RAW_TRIPLE, _RAW_TRIPLE_UNTERM, _DQ, _DQ_UNTERM,
               _CHAR),  # also Scala
    "javascript": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _BACKTICK, _DQ, _DQ_UNTERM, _SQ_STR, _SQ_UNTERM),
    "php": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _LINE_HASH, _DQ, _DQ_UNTERM, _SQ_STR, _SQ_UNTERM),
    "rust": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _RUST_RAW_OPEN, _DQ, _DQ_UNTERM, _CHAR),
    "csharp": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _CSHARP_VERBATIM, _CSHARP_VERBATIM_UNTERM, _DQ, _DQ_UNTERM,
               _CHAR),
    # Used by code.crypto_primitives (code.ts.python parses with ast instead).
    # No lexer for C/C++, Ruby or Swift on purpose: raw strings (C++ R"x(...)x",
    # Swift #"..."#), regex / %-literals and heredocs (Ruby) would let a crafted
    # literal blank real code. Those languages are scanned unstripped (fail-open).
    "python": (_PY_TRIPLE_DQ, _PY_TRIPLE_DQ_UNTERM, _PY_TRIPLE_SQ, _PY_TRIPLE_SQ_UNTERM, _LINE_HASH,
               _DQ, _DQ_UNTERM, _SQ_STR, _SQ_UNTERM),
}
# Languages whose line comments start with "#" (a "#" span is a comment there).
_HASH_COMMENT_LANGS = frozenset({"php", "python"})


# Larger inputs are not stripped (returned unchanged, fail-open toward false
# positives, never toward missed calls): bounds the work per file.
MAX_STRIP_CHARS = 2 * 1024 * 1024


# Unterminated forms that reach the end of input and whose closer does not
# depend on the opener. Once one matches, its form can never match again later
# in the file (no closer remains), so the scan resumes just past the opener
# without that form instead of leaving the rest of the file unblanked. At most
# one restart per entry, so still linear. Rust raw strings are NOT here: their
# closer depends on the hash count, so a later r"..." can still close after an
# unterminated r##"..." (dropping the form would let _DQ misread it).
_EOF_UNTERM: dict[str, tuple[str, str]] = {
    "unterm_block": (_BLOCK, _BLOCK_UNTERM),
    "unterm_verbatim": (_CSHARP_VERBATIM, _CSHARP_VERBATIM_UNTERM),
    "unterm_tb": (_JAVA_TEXT_BLOCK, _JAVA_TEXT_BLOCK_UNTERM),
    "unterm_rawtriple": (_RAW_TRIPLE, _RAW_TRIPLE_UNTERM),
    "unterm_pydq": (_PY_TRIPLE_DQ, _PY_TRIPLE_DQ_UNTERM),
    "unterm_pysq": (_PY_TRIPLE_SQ, _PY_TRIPLE_SQ_UNTERM),
}


@cache
def _pattern_for(lang: str, drop: frozenset[str] = frozenset()) -> re.Pattern[str] | None:
    """Compile (and cache) the combined comment/string pattern for ``lang``,
    without the end-of-input forms named in ``drop``."""
    forms = _LANG_FORMS.get(lang)
    if forms is None:
        return None
    dropped = {form for name in drop for form in _EOF_UNTERM[name]}
    return re.compile("|".join(f"(?:{form})" for form in forms if form not in dropped))


def _raw_last_close(source: str) -> list[int]:
    """last[h] = start of the last ``"`` followed by >= h ``#`` (-1 if none).

    A Rust raw opener with h hashes ending at e is terminated iff last[h] >= e,
    an O(1) test, so unterminated openers never trigger a scan to the end."""
    best: dict[int, int] = {}
    for m in re.finditer(r'"(#*)', source):
        best[len(m.group(1))] = m.start()
    last = [-1] * (max(best, default=0) + 1)
    running = -1
    for run in range(len(last) - 1, -1, -1):
        running = max(running, best.get(run, -1))
        last[run] = running
    return last


def _blank_spans(source: str, lang: str) -> Iterator[tuple[int, int]]:
    """(start, end) of every comment / terminated literal, left to right."""
    drop: frozenset[str] = frozenset()
    pos = 0
    raw_last: list[int] | None = None
    while (pattern := _pattern_for(lang, drop)) is not None:
        match = pattern.search(source, pos)
        if match is None:
            return
        group = match.lastgroup or ""
        if group in _EOF_UNTERM:
            drop, pos = drop | {group}, match.start() + 1
            continue
        pos = match.end()
        if group == "raw_open":
            hashes = match.group("rrhash")
            raw_last = raw_last if raw_last is not None else _raw_last_close(source)
            if len(hashes) < len(raw_last) and raw_last[len(hashes)] >= match.end():
                pos = source.find('"' + hashes, match.end()) + 1 + len(hashes)
                yield match.start(), pos
            # else unterminated: only the opener stays code; scanning goes on
            continue
        if not group.startswith("unterm"):  # unterminated quote: leave as code
            yield match.start(), match.end()


def strip_noncode(source: str, lang: str) -> str:
    """Blank comments and string/char literals in ``source`` for ``lang``.

    Returns a string of the *same length* as ``source`` in which every
    character belonging to a comment or a string/char literal is replaced by a
    space, except newlines which are preserved.  All other characters are
    copied verbatim, so byte offsets and line numbers are unchanged.

    Unknown languages, or any internal failure, return ``source`` unchanged
    (fail-open: detection recall must never regress).
    """
    try:
        if lang not in _LANG_FORMS or len(source) > MAX_STRIP_CHARS:
            return source
        chars = list(source)
        for start, end in _blank_spans(source, lang):
            for i in range(start, end):
                if chars[i] != "\n":
                    chars[i] = " "
        return "".join(chars)
    except Exception:
        # Fail-open: never let stripping drop a real detection.
        return source


def noncode_spans(source: str, lang: str) -> list[tuple[int, int]]:
    """Sorted, non-overlapping (start, end) of every comment and string literal.

    Empty (everything is code) for unknown languages, oversize input or any
    internal failure — the same fail-open rule as ``strip_noncode``."""
    if lang not in _LANG_FORMS or len(source) > MAX_STRIP_CHARS:
        return []
    try:
        return list(_blank_spans(source, lang))
    except Exception:
        return []


def is_comment_span(source: str, start: int, lang: str) -> bool:
    """True when the non-code span starting at ``start`` is a comment, not a string."""
    return source.startswith(("//", "/*"), start) or (lang in _HASH_COMMENT_LANGS and source.startswith("#", start))


def _oversize_note(probe_id: str, path: Path, source: str) -> Finding:
    return Finding(
        probe_id=probe_id,
        algorithm="N/A",
        classification=Classification.INFO,
        severity=Severity.INFO,
        title=f"{path.name}: over {MAX_STRIP_CHARS // (1024 * 1024)} MiB, scanned without comment/string stripping",
        evidence={"path": str(path), "chars": len(source)},
    )


def strip_for_scan(source: str, lang: str, *, probe_id: str, path: Path, emit: Callable[[Finding], None]) -> str:
    """``strip_noncode`` for a probe: also emits an INFO note when ``source`` is
    too large to strip, so the unstripped (noisier) scan is visible."""
    if len(source) > MAX_STRIP_CHARS:
        emit(_oversize_note(probe_id, path, source))
    return strip_noncode(source, lang)


def spans_for_scan(
    source: str, lang: str, *, probe_id: str, path: Path, emit: Callable[[Finding], None],
) -> list[tuple[int, int]]:
    """``noncode_spans`` for a probe, with the same oversize INFO note."""
    if len(source) > MAX_STRIP_CHARS:
        emit(_oversize_note(probe_id, path, source))
    return noncode_spans(source, lang)


def code_finditer(
    pattern: re.Pattern[str],
    text: str,
    scan_text: str,
) -> Iterator[re.Match[str]]:
    """Yield ``pattern`` matches over ``text`` whose anchor is real code.

    ``scan_text`` must be ``strip_noncode(text, lang)`` — same length as
    ``text`` with comment/string characters blanked to spaces.  We deliberately
    run ``finditer`` over the *original* ``text`` (not ``scan_text``) so that
    detection regexes which key off a string-literal argument — e.g.
    ``createHash('md5')`` or ``getInstance("MD5")`` — still match; those quoted
    algorithm names are blanked in ``scan_text`` and would otherwise be lost.

    A match is kept iff the character at its start offset is unchanged between
    ``text`` and ``scan_text`` (i.e. the call/identifier that anchors the match
    is code, not the interior of a comment or string literal).  A weak token
    that lives wholly inside a comment or string has its anchor blanked and is
    dropped as a false positive.
    """
    for match in pattern.finditer(text):
        i = match.start()
        # Blanked positions are exactly those where a non-newline code char was
        # turned into a space; an unchanged position is genuine code.
        if i < len(scan_text) and text[i] != scan_text[i]:
            continue
        yield match
