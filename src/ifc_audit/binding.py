"""Session/nonce/policy binding and collector attestation (host reference)."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .encoding import DOMAIN_BIND
from .poseidon import hash_const_len


@dataclass(frozen=True)
class BindingContext:
    commitment: int
    policy_id: int
    session_id: int
    nonce: int
    collector_id: int

    def canonical_bytes(self) -> bytes:
        return b"|".join(
            str(v & ((1 << 256) - 1)).encode("ascii")
            for v in (
                self.commitment,
                self.policy_id,
                self.session_id,
                self.nonce,
                self.collector_id,
            )
        )

    def binding_hash(self) -> int:
        """Domain-separated Poseidon binding value (design interface)."""
        return hash_const_len(
            [
                DOMAIN_BIND,
                self.commitment,
                self.policy_id,
                self.session_id,
                self.nonce,
            ]
        )


def generate_collector_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def collector_id_from_public_key_bytes(raw: bytes) -> int:
    """Canonical rule shared with Rust.

    collector_id = big-endian u64 of SHA256(raw public key)[0..8] & (2^63 - 1).
    """
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 raw bytes")
    digest = hashlib.sha256(raw).digest()
    return int.from_bytes(digest[:8], "big") & ((1 << 63) - 1)


def collector_id_from_public_key(key: Ed25519PublicKey) -> int:
    raw = key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return collector_id_from_public_key_bytes(raw)


def sign_attestation(key: Ed25519PrivateKey, ctx: BindingContext) -> bytes:
    return key.sign(ctx.canonical_bytes())


def verify_attestation(
    public_key: Ed25519PublicKey, ctx: BindingContext, signature: bytes
) -> bool:
    try:
        public_key.verify(signature, ctx.canonical_bytes())
        return True
    except InvalidSignature:
        return False
