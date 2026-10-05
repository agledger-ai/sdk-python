"""Console-script shim for ``agledger-verify``.

The verifier needs ``cbor2`` and ``cryptography``, which only the ``[verify]``
extra installs, but a wheel cannot make a console script conditional on an
extra: a plain ``pip install agledger`` puts ``agledger-verify`` on PATH
anyway. This shim lives outside the ``agledger.verify`` package (whose import
is what fails) so it can catch the missing dependency and say so in one line,
with its own exit code, instead of a traceback.
"""

from __future__ import annotations

import sys

# The verifier's own exit codes are 0 pass, 1 verification failure, 2 usage or
# IO error. A missing dependency is none of those, and a pipeline must not read
# it as a tamper finding.
EXIT_MISSING_EXTRA = 3


def main() -> None:
    """Entry point for ``agledger-verify``."""
    try:
        from agledger.verify.cli import main as verify_main
    except ImportError as err:
        # The library's own message names the missing package; only the
        # remedy is ours, so it is not repeated when the message carries it.
        text = str(err)
        if "agledger[verify]" not in text:
            text = f"{text} Install the verifier's dependencies with: pip install 'agledger[verify]'"
        sys.stderr.write(f"agledger-verify: {text}\n")
        sys.exit(EXIT_MISSING_EXTRA)
    verify_main()
