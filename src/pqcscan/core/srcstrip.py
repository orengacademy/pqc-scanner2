"""Language-aware comment/string blanking for regex-based source probes.

The non-Python source-code probes (``code.ts.go`` / ``.java`` (also Kotlin and
Scala) / ``.javascript`` / ``.php`` / ``.rust`` / ``.csharp``) detect weak crypto with plain regexes over raw source
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
# an unterminated block comment / raw / verbatim string to the end of input.
# They are NOT blanked (fail-open: the text stays code). Without them finditer
# retried at every later opener and rescanned the same span — quadratic, e.g.
# 10 s for one 40 k-character line of \" escapes. The group names must start
# with "unterm" (strip_noncode skips blanking on them).
_DQ_UNTERM = r'(?P<unterm_dq>"(?:\\.|[^"\\\n])*+)'
_SQ_UNTERM = r"(?P<unterm_sq>'(?:\\.|[^'\\\n])*+)"
_BLOCK_UNTERM = r"(?P<unterm_block>/\*[\s\S]*)"
_RUST_RAW_UNTERM = r'(?P<unterm_raw>b?r#*"[\s\S]*)'
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
# Rust raw string: r"...", r#"..."#, br"..."# — hash count matched via backref.
_RUST_RAW = r'(?:b?r)(?P<rrhash>#*)"[\s\S]*?"(?P=rrhash)'
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

# Per-language alternation members.  Order matters only where two forms can
# start at the same character: triple-quoted / verbatim forms precede _DQ, and
# each *_UNTERM form directly follows the form it backs up.  With those, every
# character is scanned a bounded number of times, so stripping is linear in the
# input length (pinned by timing tests in tests/unit/test_srcstrip.py).
_LANG_FORMS: dict[str, tuple[str, ...]] = {
    "go": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _BACKTICK, _DQ, _DQ_UNTERM, _CHAR),
    "java": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _JAVA_TEXT_BLOCK, _DQ, _DQ_UNTERM, _CHAR),
    "kotlin": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _RAW_TRIPLE, _DQ, _DQ_UNTERM, _CHAR),  # also Scala
    "javascript": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _BACKTICK, _DQ, _DQ_UNTERM, _SQ_STR, _SQ_UNTERM),
    "php": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _LINE_HASH, _DQ, _DQ_UNTERM, _SQ_STR, _SQ_UNTERM),
    "rust": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _RUST_RAW, _RUST_RAW_UNTERM, _DQ, _DQ_UNTERM, _CHAR),
    "csharp": (_BLOCK, _BLOCK_UNTERM, _LINE_SLASH, _CSHARP_VERBATIM, _CSHARP_VERBATIM_UNTERM, _DQ, _DQ_UNTERM,
               _CHAR),
}


# Larger inputs are not stripped (returned unchanged, fail-open toward false
# positives, never toward missed calls): bounds the work per file.
MAX_STRIP_CHARS = 2 * 1024 * 1024


# Unterminated forms that reach the end of input. Once one matches, its form can
# never match again later in the file (no closer remains), so the scan resumes
# just past the opener without that form instead of leaving the rest of the file
# unblanked. At most one restart per entry, so still linear.
_EOF_UNTERM: dict[str, tuple[str, str]] = {
    "unterm_block": (_BLOCK, _BLOCK_UNTERM),
    "unterm_raw": (_RUST_RAW, _RUST_RAW_UNTERM),
    "unterm_verbatim": (_CSHARP_VERBATIM, _CSHARP_VERBATIM_UNTERM),
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


def _blank_spans(source: str, lang: str) -> Iterator[tuple[int, int]]:
    """(start, end) of every comment / terminated literal, left to right."""
    drop: frozenset[str] = frozenset()
    pos = 0
    while (pattern := _pattern_for(lang, drop)) is not None:
        for match in pattern.finditer(source, pos):
            group = match.lastgroup or ""
            if group in _EOF_UNTERM:
                drop, pos = drop | {group}, match.start() + 1
                break
            if not group.startswith("unterm"):  # unterminated quote: leave as code
                yield match.start(), match.end()
        else:
            return


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


def strip_for_scan(source: str, lang: str, *, probe_id: str, path: Path, emit: Callable[[Finding], None]) -> str:
    """``strip_noncode`` for a probe: also emits an INFO note when ``source`` is
    too large to strip, so the unstripped (noisier) scan is visible."""
    if len(source) > MAX_STRIP_CHARS:
        emit(Finding(
            probe_id=probe_id,
            algorithm="N/A",
            classification=Classification.INFO,
            severity=Severity.INFO,
            title=f"{path.name}: over {MAX_STRIP_CHARS // (1024 * 1024)} MiB, scanned without comment/string stripping",
            evidence={"path": str(path), "chars": len(source)},
        ))
    return strip_noncode(source, lang)


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
