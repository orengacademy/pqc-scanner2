#!/usr/bin/env python3
"""libFuzzer target: the input is the bundle JSON text; it is gzipped and fed to load_bundle, so the fuzzer works
on the parser and the validators rather than on gzip. Expected rejections are BundleInvalid and BundleTooLarge;
anything else is a crash."""
import gzip
import sys

import atheris

with atheris.instrument_imports(include=["pqcscan.store.bundle", "pqcscan.core.parity"]):
    from pqcscan.store.bundle import BundleInvalid, BundleTooLarge, load_bundle


def TestOneInput(data: bytes) -> None:  # noqa: N802 - the name atheris documents
    try:
        load_bundle(gzip.compress(data, compresslevel=1))
    except (BundleInvalid, BundleTooLarge):
        return


atheris.Setup(sys.argv, TestOneInput)
atheris.Fuzz()
