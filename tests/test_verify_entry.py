"""The ``agledger-verify`` console script and the missing ``[verify]`` extra."""

import subprocess
import sys

from agledger.types import VerificationKey


def test_missing_extra_is_one_line_and_exit_3():
    """Without cbor2 the entry point prints one line naming the extra and exits
    3, where it used to die with a traceback."""
    code = (
        "import sys\n"
        "sys.modules['cbor2'] = None\n"  # makes `import cbor2` raise ImportError
        "from agledger._verify_entry import main\n"
        "main()\n"
    )
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=False)
    assert proc.returncode == 3
    assert proc.stdout == ""
    assert "Traceback" not in proc.stderr
    assert proc.stderr.count("\n") == 1
    assert proc.stderr.startswith("agledger-verify: ") and "pip install 'agledger[verify]'" in proc.stderr


def test_entry_point_runs_the_verifier_when_the_extra_is_present():
    proc = subprocess.run(
        [sys.executable, "-c", "from agledger._verify_entry import main; main()", "--help"],
        capture_output=True, text=True, check=False,
    )
    assert proc.returncode == 0
    assert "agledger-verify" in proc.stdout + proc.stderr


def test_verification_key_declares_distrusted_from():
    key = VerificationKey.model_validate(
        {
            "keyId": "k1", "algorithm": "Ed25519", "publicKey": "AA==", "status": "retired",
            "distrustedFrom": "2026-10-01T00:00:00.000Z", "statements": [],
        }
    )
    assert key.distrusted_from == "2026-10-01T00:00:00.000Z"
    assert "distrusted_from" in VerificationKey.model_fields
    absent = VerificationKey.model_validate(
        {"keyId": "k1", "algorithm": "Ed25519", "publicKey": "AA==", "status": "active", "statements": []}
    )
    assert absent.distrusted_from is None
