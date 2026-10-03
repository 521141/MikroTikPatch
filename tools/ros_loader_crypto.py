#!/usr/bin/env python3
"""RouterOS v7 loader 里的两个"私有"密码学原语 —— 纯 Python 可复现实现。

来源：IDA Pro 反编译官方 7.24.4 i386 loader，地址与长度都是 IDA 给出的权威值。

    sub_804F2D6   0x804f2d6-0x804f528 (594 字节)   license 块校验函数
    sub_804E5CF   0x804e5cf-0x804e65c (141 字节)   H(dst@eax, src@edx, len@ecx)
    sub_804E3BB   0x804e3bb-0x804e5cf (532 字节)   SHA-256 压缩函数(state@eax, block@edx)
    私有 IV       0x805b3a0 (8 dword)
    私有 K 表     0x805b3c0 (64 dword)             哈希与 ARX 共用同一张表

这两张表与 SHA-256 的标准常量**完全不同**（标准 IV 是 `6a09e667…`，标准 K 是
`428a2f98…`），所以早期一度认为"这个哈希复现不了"。其实结构就是标准 SHA-256：
它俩是 MikroTik 私有化过的常量。本轮把两张表完整提取出来之后，哈希与 ARX 都能
逐比特复现 —— 期望值见 `--selftest`，取自 Unicorn 定点仿真的实测输出。

ARM32 是同一份代码：7.24.4 的校验函数 `sub_1A9F4`(0x1a9f4-0x1ac6c)、同一个 K 表
(`0x226e8`)、同一个 IV（ARM 版把它内联成立即数存进 `sub_1A958`）。哈希/ARX 两边一致。

用法
----
    python3 tools/ros_loader_crypto.py --selftest
    python3 tools/ros_loader_crypto.py --hash 616263
    python3 tools/ros_loader_crypto.py --arx 000102030405060708090a0b0c0d0e0f
    python3 tools/ros_loader_crypto.py --un-arx 1f2b850a3123aca2dbc9badb52be9d87
    python3 tools/ros_loader_crypto.py --consistency --softid 3d67e8f8370106060000000000000000 \\
        --dmi 00000000-0000-0000-0000-000000000000 --lic <128hex>

无第三方依赖。
"""

from __future__ import annotations

import argparse
import re
import sys

M32 = 0xFFFFFFFF

# 0x805b3a0，8 个 dword，按内存里的原始值（小端）读出。
PRIVATE_IV = [
    0x5B653932, 0x7B145F8F, 0x71FFB291, 0x38EF925F,
    0x03E1AAF9, 0x4A2057CC, 0x4CAF4DD9, 0x643CC9EA,
]

# 0x805b3c0，64 个 dword；哈希当轮常量用，ARX 每轮取 4 个当子密钥兼旋转量。
PRIVATE_K = [
    0x0548D563, 0x98308EAB, 0x37AF7CCC, 0xDFBC4E3C,
    0xF125AAC9, 0xEC98ACB8, 0x8B540795, 0xD3E0EF0E,
    0x4904D6E5, 0x0DA84981, 0x9A1F8452, 0x00EB7EAA,
    0x96F8E3B3, 0xA6CDB655, 0xE7410F9E, 0x8EECB03D,
    0x9C6A7C25, 0xD77B072F, 0x6E8F650A, 0x124E3640,
    0x7E53785A, 0xE0150772, 0xC61EF4E0, 0xBC57E5E0,
    0xC0F9A285, 0xDB342856, 0x190834C7, 0xFBEB7D8E,
    0x251BED34, 0x0E9F2AAD, 0x256AB901, 0x0A5B7890,
    0x9F124F09, 0xD84A9151, 0x427AF67A, 0x8059C9AA,
    0x13EAB029, 0x3153CDF1, 0x262D405D, 0xA2105D87,
    0x9C745F15, 0xD1613847, 0x294CE135, 0x20FB0F3C,
    0x8424D8ED, 0x8F4201B6, 0x12CA1EA7, 0x2054B091,
    0x463D8288, 0xC83253C3, 0x33EA314A, 0x9696DC92,
    0xD041CE9A, 0xE5477160, 0xC7656BE8, 0x5179FE33,
    0x1F4726F1, 0x5F393AF0, 0x26E2D004, 0x6D020245,
    0x85FDF6D7, 0xB0237C56, 0xFF5FBD94, 0xA8B3F534,
]

BLOCK_MAX = 55  # 单块 SHA-256：msg + 0x80 + 8 字节长度 <= 64


def _rotr(x: int, n: int) -> int:
    n &= 31
    return ((x >> n) | (x << (32 - n))) & M32 if n else x & M32


def _rotl(x: int, n: int) -> int:
    return _rotr(x, (32 - n) & 31)


def ros_hash(msg: bytes, iv=None, k=None) -> bytes:
    """`sub_804E5CF` + `sub_804E3BB`：单块 SHA-256 结构，私有 IV/K。

    对应 C 形态（IDA 伪代码）：

        memcpy(state, IV, 32);
        memset(block, 0, 128);
        block[60] = bswap(8 * len);       // 长度字段在偏移 56..64，高位为 0
        memcpy(block, msg, len);
        block[len] = 0x80;
        sha256_compress(state, block);
        for i in 0..8: out[i] = bswap(state[i]);

    （`0x804e5cf` 只做一块，没有多块循环 —— 所以 len 必须 <= 55。）
    """
    iv = list(iv or PRIVATE_IV)
    k = list(k or PRIVATE_K)
    if len(msg) > BLOCK_MAX:
        raise ValueError("ros_hash 只实现单块，len 必须 <= %d" % BLOCK_MAX)

    blk = bytearray(64)
    blk[:len(msg)] = msg
    blk[len(msg)] = 0x80
    blk[56:64] = (8 * len(msg)).to_bytes(8, "big")

    w = [0] * 64
    for i in range(16):
        w[i] = int.from_bytes(blk[4 * i:4 * i + 4], "big")

    a, b, c, d, e, f, g, h = iv[:8]
    for i in range(64):
        if i >= 16:
            s0 = _rotr(w[i - 15], 7) ^ _rotr(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = _rotr(w[i - 2], 17) ^ _rotr(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w[i] = (s1 + w[i - 7] + s0 + w[i - 16]) & M32
        big1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25)   # Sigma1
        ch = (e & f) ^ ((~e & M32) & g)                    # Ch
        t1 = (h + big1 + ch + k[i] + w[i]) & M32
        big0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)   # Sigma0
        maj = (a & b) ^ (a & c) ^ (b & c)                  # Maj
        t2 = (big0 + maj) & M32
        h, g, f, e = g, f, e, (d + t1) & M32
        d, c, b, a = c, b, a, (t1 + t2) & M32

    state = [(v + iv[i]) & M32 for i, v in enumerate((a, b, c, d, e, f, g, h))]
    return b"".join(x.to_bytes(4, "big") for x in state)


def arx16(block: bytes, k=None) -> bytes:
    """`sub_804F2D6` 主体：16 轮 4 路 ARX 置换，4 个 dword 按大端读入/写出。

    每轮取 K[4i..4i+4) 当子密钥；**旋转量不是常数，而是子密钥的低 4 位**
    （`rol x, (k & 0xF)`）—— 这正是照着标准 SHA-256 常量表硬猜时会一路对不上的原因。
    """
    if len(block) != 16:
        raise ValueError("arx16 需要 16 字节")
    k = list(k or PRIVATE_K)
    s = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(4)]
    for i in range(16):
        p, q, r, t = i & 3, (i + 1) & 3, (i + 2) & 3, (i + 3) & 3
        k0, k1, k2, k3 = k[4 * i:4 * i + 4]

        s[r] = (s[r] - (s[p] + k0)) & M32
        v11 = (s[p] + (s[t] ^ _rotl(s[p], k0 & 0xF))) & M32
        s[t] = v11

        v12 = (s[q] - k1 - v11) & M32
        s[q] = v12
        v14 = (s[q] + (s[r] ^ _rotl(v12, k1 & 0xF))) & M32
        s[r] = v14

        s[p] = (s[p] - k2 - v14) & M32
        v16 = (s[r] + (_rotl(s[r], k2 & 0xF) ^ s[q])) & M32
        s[q] = v16

        v18 = (s[t] - k3 - v16) & M32
        s[t] = v18
        s[p] = (s[t] + (s[p] ^ _rotl(v18, k3 & 0xF))) & M32
    return b"".join(x.to_bytes(4, "big") for x in s)


def arx16_inv(block: bytes, k=None) -> bytes:
    """`arx16` 的逆 —— 逐轮倒着把 4 个子步还原回去。

    有了它就能**反向构造** license 块：先定想要的输出（前 8 字节必须等于
    `ros_hash(DMI_uuid ‖ softid)[0..8]`，第 12 字节是 level），再反算输入。
    """
    if len(block) != 16:
        raise ValueError("arx16_inv 需要 16 字节")
    k = list(k or PRIVATE_K)
    s = [int.from_bytes(block[4 * i:4 * i + 4], "big") for i in range(4)]
    for i in range(15, -1, -1):
        p, q, r, t = i & 3, (i + 1) & 3, (i + 2) & 3, (i + 3) & 3
        k0, k1, k2, k3 = k[4 * i:4 * i + 4]

        # step4 逆：s[p] <- 旧 s[p]，s[t](=v18) <- v11
        v18 = s[t]
        s[p] = ((s[p] - s[t]) ^ _rotl(v18, k3 & 0xF)) & M32
        s[t] = (s[t] + k3 + s[q]) & M32          # v16 == s[q]（step4 没动它）

        # step3 逆：s[q] <- v12，s[p] <- 旧 s[p]
        s[q] = ((s[q] - s[r]) ^ _rotl(s[r], k2 & 0xF)) & M32
        s[p] = (s[p] + k2 + s[r]) & M32

        # step2 逆：s[r] <- 旧 s[r]，s[q] <- 旧 s[q]
        s[r] = ((s[r] - s[q]) ^ _rotl(s[q], k1 & 0xF)) & M32
        s[q] = (s[q] + k1 + s[t]) & M32

        # step1 逆：s[r] <- 旧 s[r]，s[t] <- 旧 s[t]
        s[r] = (s[r] + s[p] + k0) & M32
        s[t] = ((s[t] - s[p]) ^ _rotl(s[p], k0 & 0xF)) & M32
    return b"".join(x.to_bytes(4, "big") for x in s)


def dmi_uuid_to_bytes(text: str) -> bytes:
    """还原 `0x8053b99` 处 `fscanf("%4hx%4hx-%4hx-%4hx-%4hx-%4hx%4hx%4hx")` 写进栈的那 16 字节。

    每个 `%hx` 读一个 16 位数值，按主机小端落进 2 字节，所以文本顺序不等于字节顺序。
    """
    digits = re.findall(r"[0-9A-Fa-f]{4}", text)
    if len(digits) != 8:
        raise ValueError("DMI UUID 需要 8 组 4 位十六进制，例如 12345678-1234-1234-1234-123456789abc")
    out = bytearray()
    for d in digits:
        out += int(d, 16).to_bytes(2, "little")
    return bytes(out)


def consistency_level(softid16: bytes, dmi16: bytes, lic64: bytes) -> int:
    """复现 `0x8053c03`-`0x8053c9d`：调用方对 license 的一致性判定，返回 level。

    C 形态（IDA 伪代码，`sub_8052658`）：

        out   = ros_hash(dmi16 || softid16);      // 长度 32
        saved = out[0..8];
        if (verify(lic64, out)) {                 // verify 会覆写 out
            level = out[12];
            if ((out[0..8) != 0) && (out[0..8) != saved)) level = 0;
        } else level = 0;

    `verify` 把 `lic64[0..16)` 的 ARX 结果写回 `out`，所以这里的两处 `out` 都是 ARX 输出。
    注意 `verify` 内部那处 `memcmp(H2, lic64+16, 16)` 需要曲线运算才能算出，不在本函数内
    —— 它正是被补丁 stub 掉的那处（见 docs/loader-patch.md §3.1）。
    """
    if len(softid16) != 16:
        raise ValueError("softid16 需要 16 字节")
    if len(dmi16) != 16:
        raise ValueError("dmi16 需要 16 字节")
    if len(lic64) < 16:
        raise ValueError("lic64 至少需要 16 字节")
    saved = ros_hash(dmi16 + softid16)[:8]
    arx_out = arx16(lic64[:16])
    level = arx_out[12]
    if arx_out[:8] != b"\x00" * 8 and arx_out[:8] != saved:
        return 0
    return level


# --------------------------------------------------------------------------
# 自检向量：哈希/ARX 的期望值取自 Unicorn 定点仿真的实测输出，
# 与官方 7.24.4 loader 的真实指令流逐比特一致。
# --------------------------------------------------------------------------
SELFTEST_HASH = [
    (b"", "5f530f9c77af40dc7d875db0aca5d0c0a24b02256599c711e6f0ce27e3bbd11b"),
    (b"abc", "eedef32c7ab203ae8ce03c10d65e956a296675f769297d6c5a7552e4112e58d2"),
    (bytes(32), "85631c0cc02bef8c846a7318bdf11a767887152b9fb1d992b49984aedc655763"),
]
SELFTEST_ARX = (
    "3d67e8f8370106060000000000000000",   # license 前 16 字节（software id 头）
    "1f2b850a3123aca2dbc9badb52be9d87",   # -> ARX 输出，与 Unicorn 实测一致
)


def _selftest() -> int:
    bad = 0
    print("== ros_hash ==")
    for msg, want in SELFTEST_HASH:
        got = ros_hash(msg).hex()
        ok = got == want
        bad += not ok
        print("  [{:4s}] len={:<2d} {}{}".format(
            "OK" if ok else "FAIL", len(msg), got, "" if ok else "  want " + want))
    print("== arx16 ==")
    src, want = SELFTEST_ARX
    got = arx16(bytes.fromhex(src)).hex()
    ok = got == want
    bad += not ok
    print("  [{:4s}] {} -> {}{}".format("OK" if ok else "FAIL", src, got, "" if ok else "  want " + want))
    print("== arx16_inv（往返） ==")
    back = arx16_inv(bytes.fromhex(want)).hex()
    ok = back == src
    bad += not ok
    print("  [{:4s}] {} -> {}{}".format("OK" if ok else "FAIL", want, back, "" if ok else "  want " + src))
    print("== 一致性判定（示例：DMI 全零 + softid=license 前 16 字节）==")
    softid = bytes.fromhex(src)
    dmi = bytes(16)
    lvl = consistency_level(softid, dmi, softid + bytes(48))
    print("  consistency_level -> 0x{:02x}（未满足一致性时恒为 0）".format(lvl))
    print("\n{}".format("全部通过" if not bad else "%d 项失败" % bad))
    return 1 if bad else 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="RouterOS v7 loader 私有哈希 / ARX 原语")
    ap.add_argument("--selftest", action="store_true", help="用已知向量自检")
    ap.add_argument("--hash", metavar="HEX", help="ros_hash(hex) -> 32 字节")
    ap.add_argument("--arx", metavar="HEX32", help="arx16(16 字节 hex) -> 16 字节")
    ap.add_argument("--un-arx", metavar="HEX32", dest="un_arx", help="arx16 的逆")
    ap.add_argument("--consistency", action="store_true", help="复现调用方的一致性判定")
    ap.add_argument("--softid", metavar="HEX16", help="softid 16 字节（license 前 16 字节）")
    ap.add_argument("--dmi", metavar="UUID", help="DMI product_uuid 文本或其 16 字节 hex")
    ap.add_argument("--lic", metavar="HEX", help="license 块（>=16 字节）")
    args = ap.parse_args(argv)

    if args.selftest or len(sys.argv) == 1:
        return _selftest()
    if args.hash:
        print(ros_hash(bytes.fromhex(args.hash)).hex())
    if args.arx:
        print(arx16(bytes.fromhex(args.arx)).hex())
    if args.un_arx:
        print(arx16_inv(bytes.fromhex(args.un_arx)).hex())
    if args.consistency:
        if not (args.softid and args.dmi and args.lic):
            ap.error("--consistency 需要 --softid / --dmi / --lic")
        dmi = bytes.fromhex(args.dmi) if re.fullmatch(r"[0-9A-Fa-f]{32}", args.dmi) \
            else dmi_uuid_to_bytes(args.dmi)
        lvl = consistency_level(bytes.fromhex(args.softid), dmi, bytes.fromhex(args.lic))
        print("level = 0x{:02x} ({})".format(lvl, "一致" if lvl else "被清零或不一致"))
    return 0


if __name__ == "__main__":
    sys.exit(main())
