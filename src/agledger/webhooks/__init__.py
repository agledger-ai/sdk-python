"""
AGLedger SDK — Webhook signature verification.
"""

from agledger._errors import (
    SignatureAlgorithmUnavailableError,
    SignatureVerificationError,
)
from agledger.webhooks.verify import (
    construct_event,
    construct_event_rfc9421,
    sign_payload,
    verify_rfc9421,
    verify_signature,
)

# The errors are re-exported so a receiver can import the functions and what
# they raise from one place. Handling both is not optional in a real handler,
# and making people reach into another module for the except clause is how
# documented examples end up not running.
__all__ = [
    "verify_signature",
    "construct_event",
    "sign_payload",
    "verify_rfc9421",
    "construct_event_rfc9421",
    "SignatureVerificationError",
    "SignatureAlgorithmUnavailableError",
]
