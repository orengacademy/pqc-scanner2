__version__ = "0.1.0"

# Many trust-root and email-S/MIME bundles ship certs with negative-serial
# numbers (Microsoft Code Verification Root et al.) which cryptography >= 41
# warns about and >= 45 will refuse. Until upstream cleans those up, silence
# the warning project-wide so probe output stays clean — we still inventory
# the certs while they load.
import warnings as _warnings

try:
    from cryptography.utils import (
        CryptographyDeprecationWarning,
    )

    _warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)
except ImportError:
    pass
