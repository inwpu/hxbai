#!/usr/bin/env python3
from __future__ import annotations

import argparse
import sys

_DEFAULT_CRIBS = ("FLAG{", "flag{", "CTF{", "ctf{", "HTB{", "KEY{", "FLAG_", "flag_")
_ROTS = [("none", 0)] + [("ror", r) for r in range(1, 8)] + [("rol", r) for r in range(1, 8)]
_KEYOPS = ("xor", "add", "sub", "none")
_POSTOPS = ("none", "sub", "add", "xor")


def _ror(b: int, r: int) -> int:
    b &= 0xFF
    return ((b >> r) | (b << (8 - r))) & 0xFF


def _rol(b: int, r: int) -> int:
    b &= 0xFF
    return ((b << r) | (b >> (8 - r))) & 0xFF


def _rotate(b: int, mode: str, r: int) -> int:
    if r == 0 or mode == "none":
        return b & 0xFF
    return _ror(b, r) if mode == "ror" else _rol(b, r)


def _keyop(x: int, k: int, op: str) -> int:
    if op == "xor":
        return x ^ k
    if op == "add":
        return (x + k) & 0xFF
    if op == "sub":
        return (x - k) & 0xFF
    return x & 0xFF


def decode(blob: bytes, key: bytes, klen: int, keyop: str, rot_mode: str, rot: int,
           post: str, c: int, keypos: str = "pre") -> bytes:
    out = bytearray(len(blob))
    _kl = min(klen, len(key)) if (klen and key) else 0
    for i, x in enumerate(blob):
        k = key[i % _kl] if _kl else 0
        if keypos == "pre":
            v = _rotate(_keyop(x, k, keyop), rot_mode, rot)
        else:
            v = _keyop(_rotate(x, rot_mode, rot), k, keyop)
        if post == "sub":
            v = (v - c) & 0xFF
        elif post == "add":
            v = (v + c) & 0xFF
        elif post == "xor":
            v = v ^ c
        out[i] = v & 0xFF
    return bytes(out)


def _printable(bs: bytes) -> bool:
    return all(32 <= b < 127 for b in bs)


def solve(blob: bytes, key: bytes, cribs, klen: int | None = None, limit: int = 20,
          probe_len: int = 64, max_seconds: float = 25.0):
    if not blob or not key:
        return []
    cribs_b = [c.encode() for c in cribs if c]
    if not cribs_b:
        return []
    klens = [klen] if klen else list(range(1, min(len(key), 8) + 1))
    klens = [k for k in klens if 1 <= k <= len(key)]
    if not klens:
        return []
    import time as _t
    deadline = _t.time() + max(1.0, max_seconds)
    probe = blob[:max(1, probe_len)]
    hits, seen = [], set()
    for kl in klens:
        for keypos in ("pre", "post"):
            for keyop in _KEYOPS:
                for rot_mode, rot in _ROTS:
                    if _t.time() > deadline:
                        return hits
                    for post in _POSTOPS:
                        crange = (0,) if post == "none" else range(256)
                        for c in crange:
                            out = decode(probe, key, kl, keyop, rot_mode, rot, post, c, keypos)
                            if not _printable(out) or not any(out.startswith(cb) for cb in cribs_b):
                                continue
                            full = decode(blob, key, kl, keyop, rot_mode, rot, post, c, keypos)
                            if not _printable(full):
                                continue
                            s = full.decode("ascii", "replace")
                            if s in seen:
                                continue
                            seen.add(s)
                            desc = (f"klen={kl} keypos={keypos} keyop={keyop} rot={rot_mode}{rot} "
                                    f"post={post}{'' if post == 'none' else f'(0x{c:02x})'}")
                            hits.append((s, desc))
                            if len(hits) >= limit:
                                return hits
    return hits


def _parse_bytes(hexs: str | None, path: str | None) -> bytes:
    if path:
        try:
            with open(path, "rb") as f:
                return f.read()
        except OSError as e:
            print(f"[xform-solve] 读文件失败: {e}", file=sys.stderr)
            return b""
    if hexs:
        h = "".join(ch for ch in hexs if ch not in " \t\n\r,")
        try:
            return bytes.fromhex(h)
        except ValueError:
            print(f"[xform-solve] 无效 hex(需偶数长度的十六进制): {hexs[:48]!r}", file=sys.stderr)
            return b""
    return b""


def solve_scan(blob: bytes, key: bytes, cribs, klen: int | None = None, limit: int = 20,
               max_offset: int = 16, per_off: float = 8.0):
    _blob = blob or b""
    hi = min(max(0, int(max_offset)), max(0, len(_blob) - 4))
    for off in range(0, hi + 1):
        hits = solve(_blob[off:], key, cribs, klen=klen, limit=limit, max_seconds=max(1.0, per_off))
        if hits:
            return [(s, f"{desc} @blob-off={off}") for s, desc in hits]
    return []


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="通用字节变换约束求解器(密文+key+crib→还原变换与明文)")
    ap.add_argument("--blob"); ap.add_argument("--blob-file")
    ap.add_argument("--key", default=""); ap.add_argument("--key-file")
    ap.add_argument("--klen", type=int, default=0)
    ap.add_argument("--crib", default=",".join(_DEFAULT_CRIBS),
                    help="逗号分隔的已知明文前缀(默认大小写都试)")
    ap.add_argument("--blob-off", default="0",
                    help="密文起始偏移:整数,或 'auto' 自动滑窗(试多个偏移锁定 flag 所在窗口,免手动试偏移)")
    a = ap.parse_args(argv)
    blob = _parse_bytes(a.blob, a.blob_file)
    key = _parse_bytes(a.key, a.key_file) or b"\x00"
    if not blob:
        print("需要 --blob 或 --blob-file(密文字节)", file=sys.stderr)
        return 2
    cribs = [c for c in a.crib.split(",") if c]
    _bo = (a.blob_off or "0").strip().lower()
    if _bo == "auto":
        hits = solve_scan(blob, key, cribs, klen=a.klen or None)
    else:
        try:
            _off = max(0, int(_bo))
        except ValueError:
            _off = 0
        hits = solve(blob[_off:], key, cribs, klen=a.klen or None)
    if not hits:
        print("no transform in the bounded space maps blob→(printable, crib-prefixed) plaintext; "
              "extend the crib set, re-check key bytes, or the transform is outside "
              "{keyop×rotate×const} (try analyzing the VM/routine handlers again)")
        return 1
    for s, desc in hits:
        print(f"{s}\t[{desc}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
