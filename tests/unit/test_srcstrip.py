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


def test_java_text_block_and_kotlin_raw_string_blanked():
    # Java 15+ text blocks and Kotlin raw strings share the """...""" form.
    src = 'String s = """\n    MessageDigest.getInstance("MD5")\n""";\ncode();\n'
    out = strip_noncode(src, "java")
    assert "MessageDigest" not in out
    assert "code();" in out
    assert len(out) == len(src)


def test_java_text_block_escaped_quotes_do_not_close_it():
    # \""" inside a text block is an escape; closing there would turn the real
    # closing """ into an opener that swallows the code after it (evasion).
    src = (
        'String a = """\n    x \\""" still inside\n    """;\n'
        'void f() { MessageDigest.getInstance("MD5"); }\n'
        'String b = """\n    tail\n    """;\n'
    )
    out = strip_noncode(src, "java")
    assert "MessageDigest" in out
    assert "still inside" not in out
    assert "tail" not in out


def test_java_text_block_closes_on_final_quote_run():
    src = 'String a = """\n    ends with a quote""""; code();\n'
    out = strip_noncode(src, "java")
    assert "code();" in out
    assert "quote" not in out


def test_kotlin_raw_string_closes_on_final_quote_run():
    # """x"""" holds x" — closing early leaves a stray " that pairs with a later
    # quote on the line and blanks the real call between them (evasion).
    src = 'val a = """x"""" + MessageDigest.getInstance("MD5").digest(b).size\n'
    out = strip_noncode(src, "kotlin")
    assert "MessageDigest" in out
    assert "x" not in out.split("+")[0]
    assert len(out) == len(src)


def test_kotlin_raw_string_has_no_escapes():
    src = 'val a = """C:\\path\\"""\nMessageDigest.getInstance("MD5")\n'
    out = strip_noncode(src, "kotlin")
    assert "MessageDigest" in out


def test_text_block_quote_flood_strips_in_linear_time():
    import time

    # 1 MiB Java file: an opener, 500 kB of quotes, then code-ish padding; plus an
    # unterminated block of 2-quote runs (the backtracking-prone shape).
    flood = '"""\n' + '"' * 500_000
    flood += "x" * ((1 << 20) - len(flood))
    unterminated = '"""\n' + 'a""' * 300_000
    for lang in ("java", "kotlin"):
        for src in (flood, unterminated):
            t0 = time.perf_counter()
            out = strip_noncode(src, lang)
            assert time.perf_counter() - t0 < 1.0
            assert len(out) == len(src)


def test_plain_text_block_close_still_matches():
    for lang, src in (("java", 'a = """\n  md5 \n""";\nb();\n'), ("kotlin", 'a = """md5"""\nb()\n')):
        out = strip_noncode(src, lang)
        assert "md5" not in out and "b()" in out


def test_oversize_input_is_not_stripped_and_noted():
    from pathlib import Path

    from pqcscan.core.srcstrip import MAX_STRIP_CHARS, strip_for_scan

    src = "// md5\n" + "x" * MAX_STRIP_CHARS
    notes: list = []
    out = strip_for_scan(src, "java", probe_id="code.ts.java", path=Path("big.java"), emit=notes.append)
    assert out == src
    assert len(notes) == 1 and notes[0].evidence["chars"] == len(src)
    assert strip_for_scan("// md5\n", "java", probe_id="p", path=Path("s.java"), emit=notes.append) == " " * 6 + "\n"
    assert len(notes) == 1


def _strip_seconds(src: str, lang: str) -> float:
    import time

    t0 = time.perf_counter()
    out = strip_noncode(src, lang)
    assert len(out) == len(src)
    return time.perf_counter() - t0


def test_unterminated_quote_on_a_long_line_is_linear():
    # One 1 MiB line of escaped quotes after an opening quote never closes; the
    # scan used to retry at every quote (quadratic: ~10 s at 40 k characters).
    mib = 1 << 20
    for lang in ("go", "java", "kotlin", "rust", "csharp", "javascript", "php"):
        assert _strip_seconds('x = "' + '\\"' * (mib // 2), lang) < 1.0, lang
    for lang in ("javascript", "php"):
        assert _strip_seconds("x = '" + "\\'" * (mib // 2), lang) < 1.0, lang


def test_unterminated_block_raw_and_verbatim_floods_are_linear():
    kib = 1 << 10
    assert _strip_seconds("/* x " * (256 * kib // 5), "go") < 1.0
    assert _strip_seconds('r#"' * (256 * kib // 3), "rust") < 1.0
    assert _strip_seconds('@"' + 'x""' * (256 * kib // 3), "csharp") < 1.0


def test_unterminated_quote_is_left_as_code_to_end_of_line_only():
    src = 'x = "open md5\n// md5 comment\ny = "md5";\n'
    out = strip_noncode(src, "java")
    assert out.splitlines()[0] == 'x = "open md5'      # left as code (fail-open)
    assert "md5" not in out.splitlines()[1]            # later lines still stripped
    assert "md5" not in out.splitlines()[2]


def test_unterminated_block_comment_keeps_stripping_after_it():
    # A JS regex like /^\/*/ contains "/*" with no "*/" anywhere after it.
    src = "const re = /^\\/*/;\n// crypto.createHash('md5') is forbidden\nconst s = \"md5\";\n"
    out = strip_noncode(src, "javascript")
    assert out.startswith("const re = /^\\/*/;")
    assert "md5" not in out


def test_rust_unterminated_hashed_raw_does_not_disable_later_raw_strings():
    # r##"... never closes, but a later r"\" closes at its first quote; reading it
    # as an ordinary "\"..." string would blank the real call after it (evasion).
    src = 'let a = r##"never closed\nlet b = r"\\"; md5::compute(b"x"); let c = "x";\n'
    out = strip_noncode(src, "rust")
    assert "md5::compute" in out
    assert out.splitlines()[0] == 'let a = r##"never closed'   # unterminated: left as code


def test_rust_raw_closer_needs_its_own_hash_count():
    src = 'let a = r#"a "quoted" md5"#; let b = md5::compute(x);\n'
    out = strip_noncode(src, "rust")
    assert out.count("md5") == 1 and "md5::compute(x)" in out


def test_text_block_and_raw_string_floods_are_linear():
    mib = 1 << 20
    assert _strip_seconds('"""\n' * (mib // 4), "java") < 1.0
    assert _strip_seconds('"""\n' * (mib // 4), "kotlin") < 1.0
    # openers inside a failed body (the """ of each escaped \""") used to rescan
    # to the end of input: 17 s at 64 KiB
    assert _strip_seconds('"""\n' + '\\"""\n' * (256 * 1024 // 5), "java") < 1.0
    # descending hash counts, each unterminated
    assert _strip_seconds("".join("r" + "#" * h + '"' for h in range(1400, 0, -1)), "rust") < 1.0


def test_rust_well_formed_raw_after_unterminated_hashed_raw_is_blanked():
    src = 'let a = r##"never closed\nlet b = r#"md5 inside"#; let c = md5::compute(x);\n'
    out = strip_noncode(src, "rust")
    assert out.count("md5") == 1 and "md5::compute(x)" in out
