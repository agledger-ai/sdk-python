"""Audit resource: verifiable read-trail surface (SCITT-style org-reads checkpoints)."""

from __future__ import annotations

from typing import Any

from agledger._http import AsyncHttpClient, HttpClient
from agledger.types import OrgReadsCheckpoint, OrgReadsInclusionProof, VaultCheckpoint


class OrgReadsCheckpointsResource:
    """Org-admin reads checkpoint surface: SCITT-style signed tree heads
    (``/v1/audit/org-reads/checkpoints/*``). Each cross-party admin read is
    logged into a per-org Merkle log and periodically anchored."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(self, *, limit: int | None = None) -> dict[str, Any]:
        """List recent signed checkpoints for the calling org."""
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        return self._http.get("/v1/audit/org-reads/checkpoints", params=params)

    def get(self, checkpoint_id: str) -> OrgReadsCheckpoint:
        """Get a single checkpoint by ID."""
        return OrgReadsCheckpoint.model_validate(
            self._http.get(f"/v1/audit/org-reads/checkpoints/{checkpoint_id}")
        )

    def cosign(
        self,
        checkpoint_id: str,
        *,
        witness_key_id: str,
        witness_signature: str,
    ) -> OrgReadsCheckpoint:
        """Attach a witness cosignature to a checkpoint. The witness's signature
        format/algorithm is the customer's choice; the API stores the bytes verbatim."""
        return OrgReadsCheckpoint.model_validate(
            self._http.post(
                f"/v1/audit/org-reads/checkpoints/{checkpoint_id}/cosign",
                json={"witnessKeyId": witness_key_id, "witnessSignature": witness_signature},
            )
        )

    def proof(self, checkpoint_id: str, leaf: str) -> OrgReadsInclusionProof:
        """Get the inclusion proof for a leaf within this checkpoint."""
        return OrgReadsInclusionProof.model_validate(
            self._http.get(
                f"/v1/audit/org-reads/checkpoints/{checkpoint_id}/proof",
                params={"leaf": leaf},
            )
        )


class AsyncOrgReadsCheckpointsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(self, *, limit: int | None = None) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if limit is not None: params["limit"] = limit
        return await self._http.get("/v1/audit/org-reads/checkpoints", params=params)

    async def get(self, checkpoint_id: str) -> OrgReadsCheckpoint:
        return OrgReadsCheckpoint.model_validate(
            await self._http.get(f"/v1/audit/org-reads/checkpoints/{checkpoint_id}")
        )

    async def cosign(
        self,
        checkpoint_id: str,
        *,
        witness_key_id: str,
        witness_signature: str,
    ) -> OrgReadsCheckpoint:
        return OrgReadsCheckpoint.model_validate(
            await self._http.post(
                f"/v1/audit/org-reads/checkpoints/{checkpoint_id}/cosign",
                json={"witnessKeyId": witness_key_id, "witnessSignature": witness_signature},
            )
        )

    async def proof(self, checkpoint_id: str, leaf: str) -> OrgReadsInclusionProof:
        return OrgReadsInclusionProof.model_validate(
            await self._http.get(
                f"/v1/audit/org-reads/checkpoints/{checkpoint_id}/proof",
                params={"leaf": leaf},
            )
        )


class VaultCheckpointsResource:
    """Vault checkpoint surface: per-record 6h signed Merkle anchors that survive
    audit_vault TRUNCATE/DELETE. Pair with ``records.get_audit_export()`` to
    cross-check the live chain against checkpoint anchors offline."""

    def __init__(self, http: HttpClient) -> None:
        self._http = http

    def list(
        self,
        *,
        record_id: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if record_id is not None: params["recordId"] = record_id
        if cursor is not None: params["cursor"] = cursor
        if limit is not None: params["limit"] = limit
        raw = self._http.get_page("/v1/audit-vault/checkpoints", params=params)
        raw["data"] = [VaultCheckpoint.model_validate(c) for c in raw.get("data", [])]
        return raw


class AsyncVaultCheckpointsResource:
    def __init__(self, http: AsyncHttpClient) -> None:
        self._http = http

    async def list(
        self,
        *,
        record_id: str | None = None,
        cursor: str | None = None,
        limit: int | None = None,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {}
        if record_id is not None: params["recordId"] = record_id
        if cursor is not None: params["cursor"] = cursor
        if limit is not None: params["limit"] = limit
        raw = await self._http.get_page("/v1/audit-vault/checkpoints", params=params)
        raw["data"] = [VaultCheckpoint.model_validate(c) for c in raw.get("data", [])]
        return raw


class AuditResource:
    """Audit resource: verifiable read-trail + vault-checkpoint surface.

    - ``org_reads_checkpoints``: SCITT-style cross-party read proofs.
    - ``vault_checkpoints``: per-record signed Merkle anchors used to detect
      audit_vault truncation / out-of-band tampering offline.
    """

    def __init__(self, http: HttpClient) -> None:
        self.org_reads_checkpoints: OrgReadsCheckpointsResource = OrgReadsCheckpointsResource(http)
        self.vault_checkpoints: VaultCheckpointsResource = VaultCheckpointsResource(http)


class AsyncAuditResource:
    """Audit resource: verifiable read-trail + vault-checkpoint surface.

    - ``org_reads_checkpoints``: SCITT-style cross-party read proofs.
    - ``vault_checkpoints``: per-record signed Merkle anchors used to detect
      audit_vault truncation / out-of-band tampering offline.
    """

    def __init__(self, http: AsyncHttpClient) -> None:
        self.org_reads_checkpoints: AsyncOrgReadsCheckpointsResource = AsyncOrgReadsCheckpointsResource(http)
        self.vault_checkpoints: AsyncVaultCheckpointsResource = AsyncVaultCheckpointsResource(http)
