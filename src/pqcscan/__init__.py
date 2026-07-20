__version__ = "0.9.3"

# Many trust-root and email-S/MIME bundles ship certs with negative-serial
# numbers (Microsoft Code Verification Root et al.) which cryptography >= 41
# warns about and >= 45 will refuse. Until upstream cleans those up, silence
# the warning project-wide so probe output stays clean — we still inventory
# the certs while they load.
import sys as _sys
import warnings as _warnings

try:
    from cryptography.utils import (
        CryptographyDeprecationWarning,
    )

    _warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass


# Windows ProactorEventLoop leaks subprocess transport __del__ noise at
# interpreter shutdown when openssl/nm/etc. subprocess wrappers are GC'd
# after the asyncio.run() loop has already closed. The errors are
# benign artifacts (loop already torn down), but pollute stderr with
# "RuntimeError: Event loop is closed" and "ValueError: I/O operation
# on closed pipe" stack traces. Filter only those specific shutdown
# patterns; everything else propagates normally so real bugs surface.
if _sys.platform == "win32":
    _prior_unraisablehook = _sys.unraisablehook

    def _pqcscan_unraisablehook(unraisable):
        exc_type = getattr(unraisable, "exc_type", None)
        exc_value = getattr(unraisable, "exc_value", None)
        msg = str(exc_value) if exc_value else ""
        if (
            (exc_type is RuntimeError and "Event loop is closed" in msg)
            or (exc_type is ValueError and "closed pipe" in msg)
        ):
            return
        _prior_unraisablehook(unraisable)

    _sys.unraisablehook = _pqcscan_unraisablehook
