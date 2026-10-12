from __future__ import annotations

import pytest

from src.primitives.namespace import NamespaceId, derive_namespace_id
from src.primitives.namespace_v3 import (
    DOMAIN_NAMESPACE_V3,
    NAMESPACE_V3_COMPONENT_MAX_BYTES,
    NAMESPACE_V3_ID_BYTES,
    NamespaceIdV3,
    derive_namespace_id_v3,
    namespace_v3_preimage,
)


def test_namespace_v3_known_answer_vector_and_exact_encoding() -> None:
    ledger = b"ledger-A"
    deployment = b"deployment-17"
    asset = b"asset:token:0x2222"
    expected_preimage = bytes.fromhex(
        "305053502d4e414d4553504143452d76332d5348414b4532353603"
        "080000006c65646765722d41"
        "0d0000006465706c6f796d656e742d3137"
        "1200000061737365743a746f6b656e3a307832323232"
    )
    namespace_id = derive_namespace_id_v3(ledger, deployment, asset)
    assert namespace_v3_preimage(ledger, deployment, asset) == expected_preimage
    assert namespace_id.data.hex() == (
        "28dd9d1810978d6389b853bc3f7698a1"
        "217840c80c799147628ee230aebc9723"
        "fd19464b214fa5d5d1f5c62059bda73f"
    )
    assert len(namespace_id.data) == NAMESPACE_V3_ID_BYTES == 48
    assert isinstance(namespace_id, NamespaceIdV3)


def test_namespace_v2_formula_and_known_type_remain_separate() -> None:
    v2 = derive_namespace_id(b"L" * 32, b"D" * 32, b"A" * 32)
    v3 = derive_namespace_id_v3(b"L" * 32, b"D" * 32, b"A" * 32)
    assert isinstance(v2, NamespaceId)
    assert isinstance(v3, NamespaceIdV3)
    assert v2.data != v3.data
    assert v2 != NamespaceIdV3(v2.data)


@pytest.mark.parametrize("index", [0, 1, 2])
def test_changing_each_raw_identity_descriptor_changes_output(index: int) -> None:
    values = [b"ledger-A", b"deployment-17", b"asset:token:0x2222"]
    baseline = derive_namespace_id_v3(*values)
    changed = bytearray(values[index])
    changed[0] ^= 1
    values[index] = bytes(changed)
    assert derive_namespace_id_v3(*values) != baseline


def test_order_and_length_prefixes_prevent_descriptor_boundary_ambiguity() -> None:
    first = derive_namespace_id_v3(b"a", b"bc", b"def")
    second = derive_namespace_id_v3(b"ab", b"c", b"def")
    swapped = derive_namespace_id_v3(b"bc", b"a", b"def")
    assert first != second
    assert first != swapped
    assert namespace_v3_preimage(b"a", b"bc", b"def") != namespace_v3_preimage(
        b"ab", b"c", b"def"
    )


@pytest.mark.parametrize("values", [
    (b"", b"deployment", b"asset"),
    (b"ledger", b"", b"asset"),
    (b"ledger", b"deployment", b""),
    (b"x" * (NAMESPACE_V3_COMPONENT_MAX_BYTES + 1), b"d", b"a"),
])
def test_namespace_v3_rejects_empty_or_oversized_descriptors(values) -> None:
    with pytest.raises(ValueError):
        derive_namespace_id_v3(*values)


@pytest.mark.parametrize("values", [
    ("ledger", b"deployment", b"asset"),
    (b"ledger", bytearray(b"deployment"), b"asset"),
    (None, b"deployment", b"asset"),
])
def test_namespace_v3_rejects_non_bytes(values) -> None:
    with pytest.raises(TypeError):
        derive_namespace_id_v3(*values)


def test_namespace_v3_accepts_maximum_component_length() -> None:
    value = derive_namespace_id_v3(
        b"L" * NAMESPACE_V3_COMPONENT_MAX_BYTES,
        b"D" * NAMESPACE_V3_COMPONENT_MAX_BYTES,
        b"A" * NAMESPACE_V3_COMPONENT_MAX_BYTES,
    )
    assert len(value.data) == 48


def test_namespace_v3_identifier_rejects_wrong_output_width() -> None:
    for invalid in (b"", b"x" * 47, b"x" * 49, "x" * 48):
        with pytest.raises(ValueError):
            NamespaceIdV3(invalid)  # type: ignore[arg-type]


def test_namespace_v3_domain_is_explicitly_versioned() -> None:
    assert DOMAIN_NAMESPACE_V3 == b"0PSP-NAMESPACE-v3-SHAKE256"
    preimage = namespace_v3_preimage(b"L", b"D", b"A")
    assert preimage.startswith(DOMAIN_NAMESPACE_V3 + b"\x03")
