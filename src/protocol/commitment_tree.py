"""Canonical namespace-scoped append-only commitment Merkle tree.

The tree has depth 63 because SQLite's signed INTEGER index type is the durable
ledger index representation. Leaf indices are 0 <= index < 2^63. This module
is a reference encoding; the actual proof circuit must implement these exact
SHAKE256-384 computations and bind the same index/path.
"""
from __future__ import annotations

import hashlib
from collections.abc import Sequence

from src.primitives.namespace_v3 import NamespaceIdV3

TREE_DEPTH = 63
V3_TREE_DEPTH = 32
MAX_LEAVES = (1 << TREE_DEPTH)
V3_MAX_LEAVES = (1 << V3_TREE_DEPTH)
COMMITMENT_BYTES = 48
NODE_BYTES = 48
_EMPTY_LEAF_DOMAIN = b"0PSP-COMMITMENT-EMPTY-LEAF-v1-SHAKE256"
_LEAF_DOMAIN = b"0PSP-COMMITMENT-LEAF-v1-SHAKE256"
_NODE_DOMAIN = b"0PSP-COMMITMENT-NODE-v1-SHAKE256"


class CommitmentTreeError(ValueError):
    """Invalid commitment tree input or Merkle witness."""


def _validate_depth(depth: object) -> int:
    if isinstance(depth, bool) or not isinstance(depth, int) or not 1 <= depth <= TREE_DEPTH:
        raise CommitmentTreeError(f"tree depth must be an integer in [1, {TREE_DEPTH}]")
    return depth


def _shake384(data: bytes) -> bytes:
    return hashlib.shake_256(data).digest(NODE_BYTES)


def empty_hashes(namespace_id: NamespaceIdV3, depth: int = TREE_DEPTH) -> tuple[bytes, ...]:
    """Return default subtree hashes for levels 0..depth."""
    _validate_depth(depth)
    if not isinstance(namespace_id, NamespaceIdV3):
        raise TypeError("namespace_id must be NamespaceIdV3")
    values = [_shake384(_EMPTY_LEAF_DOMAIN + b"\x01" + namespace_id.data)]
    for level in range(depth):
        values.append(node_hash(namespace_id, level, values[-1], values[-1], tree_depth=depth))
    return tuple(values)


def leaf_hash(namespace_id: NamespaceIdV3, index: int, commitment: bytes, *, tree_depth: int = TREE_DEPTH) -> bytes:
    _validate_depth(tree_depth)
    if not isinstance(namespace_id, NamespaceIdV3):
        raise TypeError("namespace_id must be NamespaceIdV3")
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < (1 << tree_depth):
        raise CommitmentTreeError(f"leaf index must be in [0, 2^{tree_depth}-1]")
    if not isinstance(commitment, bytes) or len(commitment) != COMMITMENT_BYTES:
        raise CommitmentTreeError("commitment must be exactly 48 bytes")
    return _shake384(
        _LEAF_DOMAIN + b"\x01" + namespace_id.data + index.to_bytes(8, "big") + commitment
    )


def node_hash(namespace_id: NamespaceIdV3, level: int, left: bytes, right: bytes, *, tree_depth: int = TREE_DEPTH) -> bytes:
    _validate_depth(tree_depth)
    if not isinstance(namespace_id, NamespaceIdV3):
        raise TypeError("namespace_id must be NamespaceIdV3")
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level < tree_depth:
        raise CommitmentTreeError("node level must be in [0, tree_depth-1]")
    if not isinstance(left, bytes) or len(left) != NODE_BYTES or not isinstance(right, bytes) or len(right) != NODE_BYTES:
        raise CommitmentTreeError("child hashes must each be exactly 48 bytes")
    return _shake384(
        _NODE_DOMAIN + b"\x01" + level.to_bytes(4, "big") + namespace_id.data + left + right
    )


def root_from_path(
    namespace_id: NamespaceIdV3,
    index: int,
    commitment: bytes,
    siblings: Sequence[bytes],
    *,
    tree_depth: int = TREE_DEPTH,
) -> bytes:
    """Calculate a root from exactly tree_depth bottom-up siblings."""
    _validate_depth(tree_depth)
    if not isinstance(siblings, (list, tuple)) or len(siblings) != tree_depth:
        raise CommitmentTreeError(f"membership path must contain exactly {tree_depth} siblings")
    if any(not isinstance(sibling, bytes) or len(sibling) != NODE_BYTES for sibling in siblings):
        raise CommitmentTreeError("each membership sibling must be exactly 48 bytes")
    current = leaf_hash(namespace_id, index, commitment, tree_depth=tree_depth)
    for level, sibling in enumerate(siblings):
        if (index >> level) & 1:
            current = node_hash(namespace_id, level, sibling, current, tree_depth=tree_depth)
        else:
            current = node_hash(namespace_id, level, current, sibling, tree_depth=tree_depth)
    return current


def verify_member(
    namespace_id: NamespaceIdV3,
    root: bytes,
    index: int,
    commitment: bytes,
    siblings: Sequence[bytes],
    *,
    tree_depth: int = TREE_DEPTH,
) -> bool:
    if not isinstance(root, bytes) or len(root) != NODE_BYTES:
        raise CommitmentTreeError("root must be exactly 48 bytes")
    return root_from_path(namespace_id, index, commitment, siblings, tree_depth=tree_depth) == root


class CommitmentTree:
    """In-memory model useful for deterministic vectors and generating witnesses."""

    def __init__(self, namespace_id: NamespaceIdV3, commitments: Sequence[bytes] = (), *, depth: int = TREE_DEPTH) -> None:
        self.depth = _validate_depth(depth)
        if not isinstance(namespace_id, NamespaceIdV3):
            raise TypeError("namespace_id must be NamespaceIdV3")
        self.namespace_id = namespace_id
        self._commitments: list[bytes] = []
        self._levels: list[dict[int, bytes]] = [dict() for _ in range(self.depth + 1)]
        self._defaults = empty_hashes(namespace_id, self.depth)
        for commitment in commitments:
            self.append(commitment)

    @property
    def count(self) -> int:
        return len(self._commitments)

    @property
    def root(self) -> bytes:
        return self._levels[self.depth].get(0, self._defaults[self.depth])

    def append(self, commitment: bytes) -> int:
        if self.count >= (1 << self.depth):
            raise CommitmentTreeError("commitment tree is full")
        index = self.count
        current = leaf_hash(self.namespace_id, index, commitment, tree_depth=self.depth)
        self._levels[0][index] = current
        cursor = index
        for level in range(self.depth):
            sibling = self._levels[level].get(cursor ^ 1, self._defaults[level])
            if cursor & 1:
                current = node_hash(self.namespace_id, level, sibling, current, tree_depth=self.depth)
            else:
                current = node_hash(self.namespace_id, level, current, sibling, tree_depth=self.depth)
            cursor >>= 1
            self._levels[level + 1][cursor] = current
        self._commitments.append(commitment)
        return index

    def membership_path(self, index: int) -> tuple[bytes, ...]:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < self.count:
            raise CommitmentTreeError("membership index is outside the populated tree")
        siblings = []
        cursor = index
        for level in range(TREE_DEPTH):
            siblings.append(self._levels[level].get(cursor ^ 1, self._defaults[level]))
            cursor >>= 1
        return tuple(siblings)

    def commitment_at(self, index: int) -> bytes:
        if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < self.count:
            raise CommitmentTreeError("membership index is outside the populated tree")
        return self._commitments[index]
