#!/usr/bin/env python3
"""
Xi Codec v0: reversible Xi-projection residual compressor.

Format:
  magic: b'XIC0'
  uint64 original_size
  uint32 block_size
  uint64 floor_den
  uint64 seed_live_word
  uint64 seed_A
  uint64 seed_theta_ticks
  uint64 seed_u
  uint64 seed_v
  uint32 block_count
  repeated blocks:
    uint8 mode
      0 = raw block zlib-compressed
      1 = xor residual against Xi projection, zlib-compressed
      2 = subtract residual against Xi projection mod 256, zlib-compressed
      3 = direct Xi projection block, no payload
    uint32 compressed_length
    payload bytes

Decoder regenerates the exact same Xi projection and inverts the selected block transform.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Iterable, List, Tuple

MASK = (1 << 64) - 1
MAGIC = b"XIC0"
HEADER_STRUCT = struct.Struct("<4sQ I Q Q Q Q Q Q I")
BLOCK_STRUCT = struct.Struct("<BI")

MODE_RAW_ZLIB = 0
MODE_XOR_ZLIB = 1
MODE_SUB_ZLIB = 2
MODE_XI_DIRECT = 3
MODE_NAMES = {
    MODE_RAW_ZLIB: "raw_zlib",
    MODE_XOR_ZLIB: "xi_xor_residual_zlib",
    MODE_SUB_ZLIB: "xi_sub_residual_zlib",
    MODE_XI_DIRECT: "xi_direct_no_payload",
}

@dataclass
class XiState:
    step: int = 0
    live_word: int = 1
    carry_event: int = 0
    A: int = 0
    theta_ticks: int = 0
    kappa: int = 0
    u: int = 1
    v: int = 1
    uv: int = 1
    floor_den: int = 4096
    window_ready: int = 0
    r_num: int = 1
    r_den: int = 1
    cL_num: int = (1 << 64) - 2   # uint64 representation of -2
    cR_num: int = 2
    c_den: int = 2
    lowbit: int = 1

    def clone(self) -> "XiState":
        return XiState(**asdict(self))


def u64(x: int) -> int:
    return x & MASK


def xi_step(s: XiState) -> XiState:
    """Python port of xi_full_engine_kernel.S. Mutates and returns s."""
    s.step = u64(s.step + 1)

    rax = s.live_word
    rcx = u64(-rax) & rax
    s.lowbit = rcx
    total = rax + rcx
    carry1 = 1 if total > MASK else 0
    rax = u64(total)
    # adc rax, 0 after setc: add carry-out from rax+lowbit into rax.
    if carry1:
        rax = u64(rax + 1)
    s.live_word = rax
    s.carry_event = carry1

    s.theta_ticks = u64(s.theta_ticks + 1)
    s.kappa = s.theta_ticks >> 2

    if s.carry_event:
        s.A = u64(s.A + 1)
        s.u = 1
        s.v = s.A
        s.window_ready = 0

    r12 = s.u
    r13 = s.v
    r14 = u64(r12 * r13)
    s.uv = r14

    if s.window_ready == 0:
        if r14 >= s.floor_den:
            s.window_ready = 1
        else:
            # Preserve lifted seed on carry tick; walk corridor starting next tick.
            if not s.carry_event:
                rcx = r12
                rdx = r13
                if rcx > rdx:
                    rcx, rdx = rdx, rcx
                r8 = u64(rcx + rdx)
                s.u = rdx
                s.v = r8
                r12 = rdx
                r13 = r8
                r14 = u64(r12 * r13)
                s.uv = r14

    s.r_num = 1
    s.r_den = s.uv
    s.c_den = u64(s.uv + s.uv)
    rdx = u64(s.theta_ticks * s.uv)
    s.cL_num = u64(rdx - 2)
    s.cR_num = u64(rdx + 2)
    return s


def pack_state(s: XiState) -> bytes:
    return struct.pack(
        "<17Q",
        s.step, s.live_word, s.lowbit, s.carry_event, s.A, s.theta_ticks,
        s.kappa, s.u, s.v, s.uv, s.floor_den, s.window_ready, s.r_num,
        s.r_den, s.cL_num, s.cR_num, s.c_den,
    )


def xi_projection(nbytes: int, seed: XiState | None = None) -> bytes:
    """Generate nbytes by projecting consecutive Xi states to little-endian uint64 fields."""
    s = seed.clone() if seed is not None else XiState()
    out = bytearray()
    while len(out) < nbytes:
        xi_step(s)
        out.extend(pack_state(s))
    return bytes(out[:nbytes])


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def sub_bytes(a: bytes, b: bytes) -> bytes:
    return bytes((x - y) & 0xFF for x, y in zip(a, b))


def add_bytes(a: bytes, b: bytes) -> bytes:
    return bytes((x + y) & 0xFF for x, y in zip(a, b))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encode(data: bytes, block_size: int = 4096, floor_den: int = 4096) -> tuple[bytes, dict]:
    seed = XiState(floor_den=floor_den)
    projection = xi_projection(len(data), seed)
    blocks: List[bytes] = []
    stats = {
        "original_size": len(data),
        "block_size": block_size,
        "floor_den": floor_den,
        "sha256_original": sha256(data),
        "modes": {name: 0 for name in MODE_NAMES.values()},
        "payload_bytes_by_mode": {name: 0 for name in MODE_NAMES.values()},
    }
    block_count = (len(data) + block_size - 1) // block_size
    header = HEADER_STRUCT.pack(
        MAGIC, len(data), block_size, floor_den, seed.live_word, seed.A,
        seed.theta_ticks, seed.u, seed.v, block_count,
    )
    out = bytearray(header)

    for i in range(block_count):
        lo = i * block_size
        hi = min(len(data), lo + block_size)
        block = data[lo:hi]
        pred = projection[lo:hi]

        candidates: list[tuple[int, bytes]] = []
        if block == pred:
            candidates.append((MODE_XI_DIRECT, b""))
        raw = zlib.compress(block, 9)
        xor_res = zlib.compress(xor_bytes(block, pred), 9)
        sub_res = zlib.compress(sub_bytes(block, pred), 9)
        candidates.extend([
            (MODE_RAW_ZLIB, raw),
            (MODE_XOR_ZLIB, xor_res),
            (MODE_SUB_ZLIB, sub_res),
        ])
        mode, payload = min(candidates, key=lambda x: len(x[1]) + BLOCK_STRUCT.size)
        out.extend(BLOCK_STRUCT.pack(mode, len(payload)))
        out.extend(payload)
        name = MODE_NAMES[mode]
        stats["modes"][name] += 1
        stats["payload_bytes_by_mode"][name] += len(payload)

    encoded = bytes(out)
    stats["encoded_size"] = len(encoded)
    stats["ratio_original_over_encoded"] = (len(data) / len(encoded)) if encoded else None
    stats["zlib9_size"] = len(zlib.compress(data, 9))
    stats["ratio_original_over_zlib9"] = len(data) / stats["zlib9_size"] if stats["zlib9_size"] else None
    stats["xi_vs_zlib9_delta_bytes"] = len(encoded) - stats["zlib9_size"]
    return encoded, stats


def decode(blob: bytes) -> tuple[bytes, dict]:
    if len(blob) < HEADER_STRUCT.size:
        raise ValueError("input too small")
    (magic, original_size, block_size, floor_den, seed_live_word, seed_A,
     seed_theta_ticks, seed_u, seed_v, block_count) = HEADER_STRUCT.unpack_from(blob, 0)
    if magic != MAGIC:
        raise ValueError("bad magic")
    seed = XiState(
        live_word=seed_live_word,
        A=seed_A,
        theta_ticks=seed_theta_ticks,
        u=seed_u,
        v=seed_v,
        floor_den=floor_den,
    )
    projection = xi_projection(original_size, seed)
    pos = HEADER_STRUCT.size
    out = bytearray()
    modes = {name: 0 for name in MODE_NAMES.values()}
    for i in range(block_count):
        if pos + BLOCK_STRUCT.size > len(blob):
            raise ValueError("truncated block header")
        mode, clen = BLOCK_STRUCT.unpack_from(blob, pos)
        pos += BLOCK_STRUCT.size
        payload = blob[pos:pos + clen]
        if len(payload) != clen:
            raise ValueError("truncated payload")
        pos += clen

        lo = i * block_size
        hi = min(original_size, lo + block_size)
        pred = projection[lo:hi]

        if mode == MODE_XI_DIRECT:
            block = pred
        else:
            residual = zlib.decompress(payload)
            if len(residual) != len(pred):
                raise ValueError(f"bad residual length in block {i}")
            if mode == MODE_RAW_ZLIB:
                block = residual
            elif mode == MODE_XOR_ZLIB:
                block = xor_bytes(residual, pred)
            elif mode == MODE_SUB_ZLIB:
                block = add_bytes(residual, pred)
            else:
                raise ValueError(f"unknown mode {mode}")
        out.extend(block)
        modes[MODE_NAMES[mode]] += 1
    data = bytes(out[:original_size])
    return data, {
        "original_size": original_size,
        "block_size": block_size,
        "floor_den": floor_den,
        "block_count": block_count,
        "sha256_decoded": sha256(data),
        "modes": modes,
    }


def cmd_encode(args: argparse.Namespace) -> None:
    data = Path(args.input).read_bytes()
    encoded, stats = encode(data, block_size=args.block_size, floor_den=args.floor_den)
    Path(args.output).write_bytes(encoded)
    if args.stats:
        Path(args.stats).write_text(json.dumps(stats, indent=2) + "\n")
    print(json.dumps(stats, indent=2))


def cmd_decode(args: argparse.Namespace) -> None:
    blob = Path(args.input).read_bytes()
    data, stats = decode(blob)
    Path(args.output).write_bytes(data)
    print(json.dumps(stats, indent=2))


def cmd_project(args: argparse.Namespace) -> None:
    seed = XiState(floor_den=args.floor_den)
    Path(args.output).write_bytes(xi_projection(args.nbytes, seed))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Xi Codec v0")
    sub = p.add_subparsers(dest="cmd", required=True)

    ep = sub.add_parser("encode")
    ep.add_argument("input")
    ep.add_argument("output")
    ep.add_argument("--stats")
    ep.add_argument("--block-size", type=int, default=4096)
    ep.add_argument("--floor-den", type=int, default=4096)
    ep.set_defaults(func=cmd_encode)

    dp = sub.add_parser("decode")
    dp.add_argument("input")
    dp.add_argument("output")
    dp.set_defaults(func=cmd_decode)

    pp = sub.add_parser("project")
    pp.add_argument("output")
    pp.add_argument("--nbytes", type=int, required=True)
    pp.add_argument("--floor-den", type=int, default=4096)
    pp.set_defaults(func=cmd_project)

    args = p.parse_args(argv)
    args.func(args)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
