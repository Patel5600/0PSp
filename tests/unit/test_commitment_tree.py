from __future__ import annotations

import pytest

from src.primitives.namespace_v3 import derive_namespace_id_v3
from src.protocol.commitment_tree import (
    TREE_DEPTH,
    CommitmentTree,
    CommitmentTreeError,
    empty_hashes,
    leaf_hash,
    node_hash,
    root_from_path,
    verify_member,
)

NS = derive_namespace_id_v3(b"ledger", b"deployment", b"asset")
OTHER_NS = derive_namespace_id_v3(b"ledger", b"other-deployment", b"asset")
C1 = b"\x11" * 48
C2 = b"\x22" * 48
C3 = b"\x33" * 48


def test_empty_tree_known_answer_and_namespace_domain_separation():
    assert CommitmentTree(NS).root.hex() == (
        "efb75649132e89e425c0cbe84eeb6e1e00fff61091a92e50253202e026c1fa65"
        "9b75ffc2e661edeb693eb9b2b0d6d965"
    )
    assert CommitmentTree(NS).root != CommitmentTree(OTHER_NS).root
    assert len(empty_hashes(NS)) == TREE_DEPTH + 1


def test_append_only_tree_known_answer_and_every_membership_path():
    tree = CommitmentTree(NS)
    assert tree.append(C1) == 0
    assert tree.append(C2) == 1
    assert tree.root.hex() == (
        "b2be4d6234f292d0cdd70563368218994cfbf18c1e192d2fe4b28041858646f66"
        "abc9cb8723f98f5380c98d37085896b"
    )
    assert tree.append(C3) == 2
    for index, commitment in enumerate((C1, C2, C3)):
        path = tree.membership_path(index)
        assert len(path) == TREE_DEPTH
        assert verify_member(NS, tree.root, index, commitment, path)
        assert root_from_path(NS, index, commitment, path) == tree.root


def test_membership_rejects_wrong_index_commitment_namespace_root_or_sibling():
    tree = CommitmentTree(NS, [C1, C2, C3])
    path = tree.membership_path(1)
    assert not verify_member(NS, tree.root, 0, C2, path)
    assert not verify_member(NS, tree.root, 1, C3, path)
    assert not verify_member(OTHER_NS, tree.root, 1, C2, path)
    altered = list(path)
    altered[7] = bytes([altered[7][0] ^ 1]) + altered[7][1:]
    assert not verify_member(NS, tree.root, 1, C2, altered)


def test_tree_preserves_append_only_indices_and_does_not_accept_bad_values():
    tree = CommitmentTree(NS)
    assert tree.append(C1) == 0
    assert tree.append(C2) == 1
    assert tree.commitment_at(0) == C1
    with pytest.raises(CommitmentTreeError, match="48 bytes"):
        tree.append(b"short")
    with pytest.raises(CommitmentTreeError, match="outside"):
        tree.membership_path(2)
    with pytest.raises(CommitmentTreeError, match="48 bytes"):
        leaf_hash(NS, 0, b"")
    with pytest.raises(CommitmentTreeError, match="index"):
        leaf_hash(NS, True, C1)


def test_level_specific_node_domain_and_child_order():
    defaults = empty_hashes(NS)
    assert node_hash(NS, 0, defaults[0], defaults[1]) != node_hash(NS, 1, defaults[0], defaults[1])
    assert node_hash(NS, 0, defaults[0], defaults[1]) != node_hash(NS, 0, defaults[1], defaults[0])


def test_path_shape_and_root_width_are_strict():
    tree = CommitmentTree(NS, [C1])
    with pytest.raises(CommitmentTreeError, match="exactly 63"):
        root_from_path(NS, 0, C1, [])
    with pytest.raises(CommitmentTreeError, match="exactly 48 bytes"):
        verify_member(NS, b"bad", 0, C1, tree.membership_path(0))
    with pytest.raises(CommitmentTreeError, match="exactly 48 bytes"):
        root_from_path(NS, 0, C1, [b"\x00" * 48] * 62 + [b"bad"])
