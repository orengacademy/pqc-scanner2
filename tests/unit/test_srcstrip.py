"""Unit tests for pqcscan.core.srcstrip.strip_noncode."""
from pqcscan.core.srcstrip import strip_noncode


def test_line_comment_blanked():
    src = "x = 1 // md5 here\n"
    out = strip_noncode(src, "go")
    assert "md5" not in out
    # Code before the comment is preserved verbatim.
    assert out.startswith("x = 1 ")
    # The comment region is spaces, newline preserved.
    assert out.endswith(" \n")


def test_block_comment_blanked_multiline():
    src = "a\n/* md5\n sha1 */\nb\n"
    out = strip_noncode(src, "java")
    assert "md5" not in out
    assert "sha1" not in out
    # Real code lines survive.
    assert out.startswith("a\n")
    assert out.endswith("\nb\n")


def test_string_literal_blanked():
    src = 'v = "md5 is weak"\n'
    out = strip_noncode(src, "javascript")
    assert "md5" not in out
    assert out.startswith("v = ")


def test_slashes_inside_string_not_treated_as_comment():
    # A `//` inside a string must be blanked as string content, and the code
    # that follows the closing quote must stay intact (proves the string
    # alternative wins over the comment alternative at that position).
    src = 'url = "http://x" ; real_code()\n'
    out = strip_noncode(src, "javascript")
    # The string (including the //) is blanked...
    assert "http" not in out
    # ...but code after the closing quote is preserved, i.e. the `//` did not
    # start a comment that ate the rest of the line.
    assert "real_code()" in out


def test_newline_count_preserved():
    src = "a\n// c\n/* x\ny */\nb\n"
    out = strip_noncode(src, "go")
    assert out.count("\n") == src.count("\n")


def test_output_length_equals_input_length():
    src = 'foo("bar") // baz\n/* block */\n`raw`\n'
    for lang in ("go", "java", "javascript", "php", "rust"):
        out = strip_noncode(src, lang)
        assert len(out) == len(src), lang


def test_fail_open_on_empty_string():
    assert strip_noncode("", "go") == ""


def test_unknown_language_returns_source_unchanged():
    src = 'x = "md5" // c\n'
    assert strip_noncode(src, "cobol") == src


def test_php_hash_line_comment():
    src = "$x = 1; # md5('y')\n"
    out = strip_noncode(src, "php")
    assert "md5" not in out
    assert out.startswith("$x = 1; ")


def test_go_backtick_raw_string_blanked():
    src = "s := `md5 in raw`\ncode()\n"
    out = strip_noncode(src, "go")
    assert "md5" not in out
    assert "code()" in out


def test_rust_char_literal_does_not_break_lifetime():
    # Lifetimes (&'a T) must not be swallowed as char literals.
    src = "fn f<'a>(x: &'a str) -> &'a str { x }\n"
    out = strip_noncode(src, "rust")
    # The struct/fn code is preserved (nothing wrongly blanked between ticks).
    assert "fn f" in out
    assert "str { x }" in out


def test_never_raises_returns_same_length():
    # A pathological input (unterminated string) must not raise and length holds.
    src = 'let x = "unterminated md5\nmd5::compute();\n'
    out = strip_noncode(src, "rust")
    assert len(out) == len(src)
