#!/usr/bin/env python3
"""libFuzzer target: the input is handed to load_bundle as the gzip body, so the fuzzer works on the gzip framing,
the size caps and the truncation check as well as the JSON behind them. Expected rejections are BundleInvalid and
BundleTooLarge; anything else is a crash."""
import sys

import atheris

with atheris.instrument_imports(include=["pqcscan.store.bundle", "pqcscan.core.parity"]):
    from pqcscan.store.bundle import BundleInvalid, BundleTooLarge, load_bundle


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name atheris documents
    try:
        load_bundle(data)
    except (BundleInvalid, BundleTooLarge):
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
