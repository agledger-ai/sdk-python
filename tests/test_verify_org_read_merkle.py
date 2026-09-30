"""The org_admin_reads tree is RFC 9162 section 2.1 over the bytes each hex
hash denotes. A port of verify-core's ``org-read-merkle.test.ts``: the
reference below is written from the RFC and the route's published rule, with no
reference to the verifier, so a shared mistake cannot pass both halves. The
corpus section checks the primitives against leaves and signed tree heads the
engine wrote."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from agledger.verify import (
    org_read_leaf_hash,
    org_read_merkle_root,
    verify_org_read_inclusion,
)


def _sha256(*parts: bytes) -> bytes:
    return hashlib.sha256(b"".join(parts)).digest()


def _leaf(data: bytes) -> str:
    return _sha256(b"\x00", data).hex()


def _node(left: str, right: str) -> str:
    return _sha256(b"\x01", bytes.fromhex(left), bytes.fromhex(right)).hex()


def _split(n: int) -> int:
    k = 1
    while k * 2 < n:
        k *= 2
    return k


def _mth(leaves: list[str]) -> str:
    if not leaves:
        return hashlib.sha256(b"").hexdigest()
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node(_mth(leaves[:k]), _mth(leaves[k:]))


def _path(m: int, leaves: list[str]) -> list[str]:
    """RFC 9162 section 2.1.3.1 PATH(m, D[n]), leaf to root."""
    if len(leaves) <= 1:
        return []
    k = _split(len(leaves))
    if m < k:
        return [*_path(m, leaves[:k]), _mth(leaves[k:])]
    return [*_path(m - k, leaves[k:]), _mth(leaves[:k])]


def _data(i: int) -> bytes:
    return f"cose-sign1-{i}".encode()


SIZES = [1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 33, 100]


def test_the_leaf_hash_is_sha256_of_0x00_and_the_cose_sign1() -> None:
    assert org_read_leaf_hash(_data(0)) == _leaf(_data(0))


def test_the_empty_tree_is_sha256_of_nothing() -> None:
    assert org_read_merkle_root([]) == hashlib.sha256(b"").hexdigest()


@pytest.mark.parametrize("n", SIZES)
def test_a_root_and_every_inclusion_path_agree_with_the_rfc(n: int) -> None:
    leaves = [org_read_leaf_hash(_data(i)) for i in range(n)]
    root = _mth(leaves)
    assert org_read_merkle_root(leaves) == root
    for i in range(n):
        assert verify_org_read_inclusion(leaves[i], i, n, _path(i, leaves), root), f"leaf {i} of {n}"


def test_a_one_leaf_tree_has_an_empty_path_and_its_root_is_the_leaf() -> None:
    leaf = org_read_leaf_hash(_data(0))
    assert org_read_merkle_root([leaf]) == leaf
    assert verify_org_read_inclusion(leaf, 0, 1, [], leaf)
    assert not verify_org_read_inclusion(leaf, 0, 1, [leaf], leaf)


def test_an_altered_path_entry_a_wrong_leaf_a_surplus_entry_or_an_out_of_range_index_breaks_the_walk() -> None:
    leaves = [org_read_leaf_hash(_data(i)) for i in range(100)]
    root = _mth(leaves)
    proof = _path(42, leaves)
    mauled = list(proof)
    mauled[1] = mauled[1][:63] + ("1" if mauled[1].endswith("0") else "0")
    assert not verify_org_read_inclusion(leaves[42], 42, 100, mauled, root)
    assert not verify_org_read_inclusion(leaves[43], 42, 100, proof, root)
    assert not verify_org_read_inclusion(leaves[42], 42, 100, [*proof, proof[0]], root)
    assert not verify_org_read_inclusion(leaves[42], 100, 100, proof, root)


def test_refuses_a_leaf_index_or_tree_size_that_is_not_a_safe_integer() -> None:
    leaves = [org_read_leaf_hash(_data(0)), org_read_leaf_hash(_data(1))]
    root = _mth(leaves)
    proof = _path(0, leaves)
    assert verify_org_read_inclusion(leaves[0], 0, 2, proof, root)
    bad: list[tuple[Any, Any]] = [
        (float("nan"), 2),
        (0.5, 2),
        (0, float("nan")),
        (0, 2.5),
        (0, float("inf")),
        (-0.5, 2),
        (0, 2**53),
        (True, 2),
    ]
    for index, size in bad:
        assert not verify_org_read_inclusion(leaves[0], index, size, proof, root), f"leaf_index {index}, tree_size {size}"


def test_walks_a_tree_past_2_32_leaves_without_wrapping_the_index_or_the_size() -> None:
    # PATH(m, D[n]) needs only the sibling subtree hashes, so any values stand
    # in for them; the root is folded from the definition.
    def depth(m: int, n: int) -> int:
        if n == 1:
            return 0
        k = _split(n)
        return 1 + (depth(m, k) if m < k else depth(m - k, n - k))

    def root_of(leaf: str, m: int, n: int, siblings: list[str]) -> str:
        if n == 1:
            return leaf
        k = _split(n)
        last, rest = siblings[-1], siblings[:-1]
        return _node(root_of(leaf, m, k, rest), last) if m < k else _node(last, root_of(leaf, m - k, n - k, rest))

    leaf = org_read_leaf_hash(_data(8))
    for m, n in ((2**32, 2**32 + 1), (5, 2**32 + 7), (2**32 + 3, 2**32 + 7), (2**40 + 1, 2**41 - 3)):
        siblings = [org_read_leaf_hash(_data(100 + i)) for i in range(depth(m, n))]
        root = root_of(leaf, m, n, siblings)
        assert verify_org_read_inclusion(leaf, m, n, siblings, root), f"leaf {m} of {n}"
        assert not verify_org_read_inclusion(leaf, m + 1, n, siblings, root), f"leaf {m + 1} of {n}"


def test_hashing_the_hex_text_instead_of_the_bytes_it_denotes_does_not_reproduce_the_root() -> None:
    leaves = [org_read_leaf_hash(_data(i)) for i in range(5)]
    over_text = hashlib.sha256(b"\x01" + (leaves[0] + leaves[1]).encode()).hexdigest()
    assert over_text != _node(leaves[0], leaves[1])
    assert org_read_merkle_root(leaves[:2]) == _node(leaves[0], leaves[1])


def test_refuses_a_value_that_is_not_64_lowercase_hex_characters() -> None:
    leaf = org_read_leaf_hash(_data(0))
    assert org_read_merkle_root([leaf, leaf.upper()]) is None
    assert org_read_merkle_root([leaf, "zz"]) is None
    assert not verify_org_read_inclusion(leaf[2:], 0, 1, [], leaf)


_DUMP_DIR = Path(__file__).resolve().parents[1] / "testdata" / "conformance" / "dump"


def _ndjson(vector: str, name: str) -> list[dict[str, Any]]:
    text = (_DUMP_DIR / vector / name).read_text()
    return [json.loads(line) for line in text.splitlines() if line.strip()]


@pytest.mark.parametrize("vector", ["valid", "valid-unsigned-history-then-signed", "valid-key-succession", "valid-es256"])
def test_every_stored_leaf_hash_and_every_signed_root_recompute_over_the_engine_corpus(vector: str) -> None:
    leaves = _ndjson(vector, "org_admin_reads.ndjson")
    heads = _ndjson(vector, "org_admin_reads_checkpoints.ndjson")
    assert leaves
    assert heads
    for leaf in leaves:
        assert org_read_leaf_hash(base64.b64decode(leaf["cose_sign1"])) == leaf["leaf_hash"]
    for head in heads:
        ordered = [
            leaf["leaf_hash"]
            for leaf in sorted((x for x in leaves if x["org_id"] == head["org_id"]), key=lambda x: x["leaf_index"])
        ]
        covered = ordered[: head["tree_size"]]
        assert org_read_merkle_root(covered) == head["root_hash"]
        for i in range(head["tree_size"]):
            assert verify_org_read_inclusion(covered[i], i, head["tree_size"], _path(i, covered), head["root_hash"])


def test_the_tampered_root_does_not_recompute() -> None:
    leaves = _ndjson("tenant-checkpoint-root-mismatch", "org_admin_reads.ndjson")
    heads = _ndjson("tenant-checkpoint-root-mismatch", "org_admin_reads_checkpoints.ndjson")
    mismatched = [
        head
        for head in heads
        if org_read_merkle_root(
            [
                x["leaf_hash"]
                for x in sorted((x for x in leaves if x["org_id"] == head["org_id"]), key=lambda x: x["leaf_index"])
            ][: head["tree_size"]]
        )
        != head["root_hash"]
    ]
    assert mismatched
