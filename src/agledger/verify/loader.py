"""NDJSON dump-directory loader. Reads the five expected files and returns a
typed :class:`Dump`. A missing file raises :class:`DumpLoadError` rather than
producing a silent empty array: a verifier that reports OK on a half-empty dump
is the wrong default. Mirrors the TS ``loader.ts``.

Row shapes are NOT validated beyond JSON parsing: the verifier itself catches
semantic problems, so schema-level pickiness here would just duplicate the chain
checks.
"""

from __future__ import annotations

import json
import os
from typing import Any

from agledger.verify.types import Dump, DumpRow


class DumpLoadError(Exception):
    """A dump directory is missing a required file or carries malformed NDJSON.

    Distinct from a verification failure: this is an input/IO problem (the CLI
    maps it to exit code 2), not evidence of tamper.
    """


#: The five required files, in (attribute, filename) form.
DEFAULT_FILENAMES: dict[str, str] = {
    "vault_entries": "audit_vault.ndjson",
    "vault_checkpoints": "vault_checkpoints.ndjson",
    "signing_keys": "vault_signing_keys.ndjson",
    "org_admin_reads": "org_admin_reads.ndjson",
    "org_admin_reads_checkpoints": "org_admin_reads_checkpoints.ndjson",
}


def _read_ndjson(path: str) -> list[DumpRow]:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    except FileNotFoundError as err:
        raise DumpLoadError(f"Required dump file not found: {path}") from err

    out: list[DumpRow] = []
    for i, line in enumerate(raw.split("\n")):
        if not line.strip():
            continue
        try:
            parsed: Any = json.loads(line)
        except json.JSONDecodeError as err:
            raise DumpLoadError(f"Invalid JSON on line {i + 1} of {path}: {err}") from err
        out.append(parsed)
    return out


def load_dump(dump_dir: str, filenames: dict[str, str] = DEFAULT_FILENAMES) -> Dump:
    """Load a five-file NDJSON dump directory into a :class:`Dump`.

    :raises DumpLoadError: if a required file is missing or a line is malformed.
    """
    return Dump(
        vault_entries=_read_ndjson(os.path.join(dump_dir, filenames["vault_entries"])),
        vault_checkpoints=_read_ndjson(os.path.join(dump_dir, filenames["vault_checkpoints"])),
        signing_keys=_read_ndjson(os.path.join(dump_dir, filenames["signing_keys"])),
        org_admin_reads=_read_ndjson(os.path.join(dump_dir, filenames["org_admin_reads"])),
        org_admin_reads_checkpoints=_read_ndjson(
            os.path.join(dump_dir, filenames["org_admin_reads_checkpoints"])
        ),
    )
