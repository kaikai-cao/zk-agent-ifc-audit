"""Poseidon P128Pow5T3 over the Pallas base field (width 3, rate 2).

Constants are extracted from halo2_poseidon 0.2.0 `src/fp.rs` and the
permutation is checked against the crate's canonical test vector.  This module
is the Phase 1A host-side mirror of the Phase 1B Halo2 gadget.

Raw four-limb constants in `fp.rs` are already canonical field integers.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

_PARAMS_PATH = Path(__file__).with_name("poseidon_params.json")


@lru_cache(maxsize=1)
def _params() -> tuple[int, tuple[tuple[int, ...], ...], tuple[tuple[int, ...], ...]]:
    data = json.loads(_PARAMS_PATH.read_text(encoding="utf-8"))
    p = int(data["p"], 16)
    rc = tuple(tuple(int(x, 16) for x in row) for row in data["round_constants"])
    mds = tuple(tuple(int(x, 16) for x in row) for row in data["mds"])
    return p, rc, mds


def permute(state: tuple[int, int, int]) -> tuple[int, int, int]:
    """One Poseidon permutation (8 full + 56 partial + 8 full rounds)."""
    p, rc, mds = _params()
    s = list(state)

    def apply_mds(st: list[int]) -> list[int]:
        return [sum(mds[i][j] * st[j] for j in range(3)) % p for i in range(3)]

    def full(st: list[int], r: tuple[int, ...]) -> list[int]:
        return apply_mds([pow((st[i] + r[i]) % p, 5, p) for i in range(3)])

    def partial(st: list[int], r: tuple[int, ...]) -> list[int]:
        st = [(st[i] + r[i]) % p for i in range(3)]
        st[0] = pow(st[0], 5, p)
        return apply_mds(st)

    rounds = [("f", r) for r in rc[:4]]
    rounds += [("p", r) for r in rc[4:60]]
    rounds += [("f", r) for r in rc[60:]]
    assert len(rounds) == 64
    for kind, r in rounds:
        s = full(s, r) if kind == "f" else partial(s, r)
    return (s[0], s[1], s[2])


def hash_const_len(values: list[int] | tuple[int, ...]) -> int:
    """ConstantLength<L> sponge hash with output length 1 (halo2_poseidon API)."""
    p, _, _ = _params()
    vals = [int(v) % p for v in values]
    length = len(vals)
    if length == 0:
        raise ValueError("Poseidon ConstantLength requires at least one input")
    # capacity = L * 2^64, output length 1
    state = (0, 0, (length << 64) % p)
    padded = vals + [0] * ((2 - length % 2) % 2)
    for i in range(0, len(padded), 2):
        chunk = padded[i : i + 2]
        state = permute((state[0] + chunk[0], state[1] + chunk[1], state[2]))
        state = (state[0] % p, state[1] % p, state[2] % p)
    return state[0]


def field_to_bytes32(value: int) -> bytes:
    return (value % _params()[0]).to_bytes(32, "little")
