"""Language-aware comment/string blanking for regex-based source probes.

The non-Python source-code probes (``code.ts.go`` / ``.java`` / ``.javascript``
/ ``.php`` / ``.rust``) detect weak crypto with plain regexes over raw source
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
- JavaScript template-literal ``${ ... }`` interpolations are blanked wholesale
  (the embedded expression is treated as string content).
- PHP heredoc/nowdoc (``<<<EOT``) bodies are not stripped.
- Multi-char Rust/Go char escapes such as ``'\\u{1F600}'`` are not matched.
"""
from __future__ import annotations

import re
from collections.abc import Iterator
from functools import cache

# --- Lexical building blocks -------------------------------------------------
# Double-quoted string with backslash escapes, confined to a single line so an
# unterminated quote fails to match (and is thus left as code — fail-open).
_DQ = r'"(?:\\.|[^"\\\n])*"'
# Single-quoted *string* (JS / PHP): multi-character, backslash escapes.
_SQ_STR = r"'(?:\\.|[^'\\\n])*'"
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

# Per-language alternation members.  Order is immaterial for correctness (the
# left-to-right scan disambiguates by start position; block vs line comments
# disambiguate on their second character) but roughly follows likelihood.
_LANG_FORMS: dict[str, tuple[str, ...]] = {
    "go": (_BLOCK, _LINE_SLASH, _BACKTICK, _DQ, _CHAR),
    "java": (_BLOCK, _LINE_SLASH, _DQ, _CHAR),
    "javascript": (_BLOCK, _LINE_SLASH, _BACKTICK, _DQ, _SQ_STR),
    "php": (_BLOCK, _LINE_SLASH, _LINE_HASH, _DQ, _SQ_STR),
    "rust": (_BLOCK, _LINE_SLASH, _RUST_RAW, _DQ, _CHAR),
}


@cache
def _pattern_for(lang: str) -> re.Pattern[str] | None:
    """Compile (and cache) the combined comment/string pattern for ``lang``."""
    forms = _LANG_FORMS.get(lang)
    if forms is None:
        return None
    combined = "|".join(f"(?:{form})" for form in forms)
    return re.compile(combined)


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
        pattern = _pattern_for(lang)
        if pattern is None:
            return source
        chars = list(source)
        for match in pattern.finditer(source):
            for i in range(match.start(), match.end()):
                if chars[i] != "\n":
                    chars[i] = " "
        return "".join(chars)
    except Exception:
        # Fail-open: never let stripping drop a real detection.
        return source


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
