#!/usr/bin/env python3
"""RouterOS `nova/bin/loader` 补丁 —— 独立实现，替代作者加密的 loader.7z 私有模块。

支持架构：i386（v7 x86 / v6 x86）与 ARM32（v7 arm，aarch32 EABI5）。

## 作者原方案（逆向自官方/发布产物的逐字节对比，7.18.2 / 7.20.8 / 7.23.7 / 7.24.2~7.24.4 全覆盖）

`loader.7z` 里的 `loader/patch_loader.py` 对 `nova/bin/loader` 做了这些事：

1. 追加一个 RWE 段：文件偏移 `0x15000`、vaddr `0x805e000`、大小 1076 字节
   （7.23.7~7.24.5 四个版本的段字节 sha256 完全相同：`d312add8988c4a0f...`）。
2. 改写元数据：牺牲 `phdr[9]`（PT_GNU_STACK）把它变成指向新段的 PT_LOAD，
   `e_entry` 从 `0x804ccc0` 改到 `0x805e000`，`e_shnum` 24→25 并在段表尾补一条装饰性
   SHT_PROGBITS 记录。文件因此从 84220 涨到 87092 字节。
3. 段内代码（逐条已反汇编确认）：
   - 用密钥 `0xa9` 就地解出混淆字符串，公式 `out[i] = ((in[i]-1) & 0xff) ^ (0xa9 ^ i)`，
     解出 `/pckg/option/bin/bash`、`/rw/disk/rc.local`、`/nova/bin/mode2`、
     `/pckg/option/bin/keygen`、`/dev/console`、`/proc/self/mem`；
   - `access()` 探测后 `execve()` 执行 `keygen` 与 `rc.local`（CHR/自定义脚本场景用）；
   - 校验 `/nova/bin/mode2` 的指纹表（8 条 `offset:4 len:1 data:len`，offset 依次为
     0x5e23/0x5e2d/0x5e37/0x5e41/0x5e4b/0x5e55/0x5e5c/0x5e63，即 `nova/bin/mode` 里
     license 公钥被打散成 8 条 x86 立即数的位置）；
   - 校验通过后把 **`memcmp` 的 GOT 槽**（`0x0805d014`，由 `.rel.plt` 决定）
     指向 `xor eax,eax; ret`，使进程内**所有 memcmp 恒返回 0**；
   - 用 `/proc/self/mem` 把 ELF 头、`e_shnum`、`phdr[9]` 在**进程内存里**还原成未篡改的样子，
     再把控制权交回原 `e_entry`。

## 这个 memcmp 到底挡的是哪一处校验（本轮新结论）

对官方 loader 做全量 `call memcmp@plt` 交叉引用（`--audit`），结论在**所有版本、所有架构上一致**：

    i386  7.15.3 / 7.17 / 7.18.2 / 7.19.1 / 7.20beta4 / 7.20.8 /
          7.23.7 / 7.24.2 / 7.24.3 / 7.24.4 …  均只有 1 处调用点
    ARM32 7.15.3 0x1d5d8、7.24.4 0x1ac58      各只有 1 处调用点
    v6 i386 0x805658f                          只有 1 处调用点

并且没有任何地方把 memcmp 的 GOT 地址当字面量使用（`0x805d014` 全文件只出现在
PLT 桩的 `ff 25` 操作数和 `.rel.plt` 里），所以 **PLT 桩就是唯一入口**。

唯一那处调用点落在 license 校验函数里（Ghidra 反编译，7.24.4 官方版 `FUN_0804f2d6`）：

    bool verify_lic_block(uint *blob, uint *out16)
    {
      w = BE(blob[0..0x10]);                       // 16 字节密文
      for (i = 0; i < 16; i++)  arx_round(w, S + 4*i);   // S = .rodata 0x805b3c0 的 64 dword 常量表
      BE_store(out16, w);                          // out16 = 解密出的 16 字节（含 license level）
      memcpy(x, out16, 0x10);                      // x 是 32 字节缓冲
      x[8..0x18] ^= blob[0x10..0x20];              // 用签名区做掩码
      x[0]  &= 0xf8;                               // ┐ Curve25519 标量 clamp
      x[31]  = (x[31] & 0x7f) | 0x40;              // ┘
      r = curve_op(x, LICENSE_PUBKEY);             // FUN_0804e9ff，内嵌 8E1067E4… 公钥
      memcpy(x, r, 0x20);
      return memcmp(x, blob + 0x10, 0x10) == 0;    // ← 全文件唯一的 memcmp
    }

调用方（7.24.4 `0x8053c5b`）语义：

    if (verify_lic_block(blob, out)) {
        lic->field_0x90 = out[12];      // 解密块第 12 字节 = license level，写进许可证结构体
        ...
    }

ARM32 版本（7.24.4 `0x1ac58`）逐条对应：同样的 16 字节 XOR 循环、同样的 byte0/byte31
clamp（`bic r3,r3,#7` / `and r3,r3,#0x7f ; orr r3,#0x40`）、同样的三次调用，末尾
`clz r0,r0 ; lsr r0,r0,#5` 就是 x86 的 `test eax,eax ; sete al`——返回值同样是
"memcmp == 0"。所以两个架构上"把 memcmp 打掉"是同一件事。

## 本模块为什么可以更简单

上面第 3 条里唯一对「绕过校验」有实质作用的是 **memcmp 恒等**；新段、`mode2` 指纹、
wrapper 转发都是作者用来保证「补丁集完整」和跑 CHR 自定义脚本的附加机制。

因此本模块直接把 `memcmp` 的 **PLT 桩**改成"返回 0"：

- i386：`ff 25 <got> 68 .. e9 ..` → `31 c0 c3` + 13×`90`（`xor eax,eax; ret`）
- ARM32：`add ip,pc,#imm` / `add ip,ip,#imm` / `ldr pc,[ip,#imm]!`（12 字节）
  → `mov r0,#0` / `bx lr` / `mov r0,r0`（`00 00 a0 e3 1e ff 2f e1 00 00 a0 e1`）

效果与作者方案**完全等价**（PLT 桩被改写后，调用点根本不会走到 GOT 槽）；
**文件长度不变**，不新增段、不改 e_entry/phdr/shnum；**不需要 `mode2`、不需要 wrapper**，
于是 `nova/bin/mode` 可以直接就地打公钥补丁。GOT 槽/PLT 桩地址全部从 `.rel.plt`
与段表动态解析，不硬编码任何版本相关常量。

## 用法

    from tools.loader_patch import patch_loader_file
    patch_loader_file('squashfs-root/nova/bin/loader')

命令行：

    python3 tools/loader_patch.py squashfs-root/nova/bin/loader      # 打补丁
    python3 tools/loader_patch.py --audit squashfs-root/nova/bin/loader   # 只做逆向体检
"""

from __future__ import annotations

import struct
import sys

ELF32 = 1
EM_386 = 3
EM_ARM = 40
SHT_PROGBITS = 1
SHT_STRTAB = 3
SHT_REL = 9
SHT_DYNSYM = 11
SHF_EXECINSTR = 0x4

# 官方 license 文件公钥（loader / mode / keyman 内嵌，存在两种存储布局）
LICENSE_PUBKEY = bytes.fromhex(
    "8E1067E4305FCDC0CFBF95C10F96E5DFE8C49AEF486BD1A4E2E96C27F01E3E32".lower())


def p32(v: int) -> bytes:
    return struct.pack("<I", v & 0xFFFFFFFF)


def _ror(v: int, r: int) -> int:
    v &= 0xFFFFFFFF
    if not r:
        return v
    return ((v >> r) | (v << (32 - r))) & 0xFFFFFFFF


def _arm_imm12(v: int) -> int:
    """解码 ARM 数据处理指令的 imm12（8 位立即数 + 循环右移）。"""
    return _ror(v & 0xFF, ((v >> 8) & 0xF) * 2)


class Elf32:
    """最小可用的 ELF32 只读视图：够解析重定位、定位 PLT 桩、扫描调用点。"""

    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("不是 ELF 文件")
        if data[4] != ELF32:
            raise ValueError("只支持 ELF32")
        self.data = data
        self.machine, = struct.unpack_from("<H", data, 0x12)
        self.entry, = struct.unpack_from("<I", data, 0x18)
        self.phoff, = struct.unpack_from("<I", data, 0x1C)
        self.shoff, = struct.unpack_from("<I", data, 0x20)
        self.phentsize, self.phnum = struct.unpack_from("<HH", data, 0x2A)
        self.shentsize, self.shnum = struct.unpack_from("<HH", data, 0x2E)
        self.sections = self._parse_sections()

    @property
    def arch(self) -> str:
        return {EM_386: "i386", EM_ARM: "arm"}.get(self.machine, f"machine{self.machine}")

    def _parse_sections(self):
        out = []
        for i in range(self.shnum):
            o = self.shoff + i * self.shentsize
            if o + 40 > len(self.data):
                break
            f = struct.unpack_from("<10I", self.data, o)
            out.append(dict(index=i, name=f[0], type=f[1], flags=f[2], addr=f[3],
                            off=f[4], size=f[5], link=f[6], info=f[7],
                            align=f[8], entsize=f[9]))
        return out

    def programs(self):
        out = []
        for i in range(self.phnum):
            o = self.phoff + i * self.phentsize
            f = struct.unpack_from("<8I", self.data, o)
            out.append(dict(index=i, type=f[0], off=f[1], vaddr=f[2], paddr=f[3],
                            filesz=f[4], memsz=f[5], flags=f[6], align=f[7]))
        return out

    def code_sections(self):
        """可执行的 PROGBITS 段（按地址升序）。"""
        secs = [s for s in self.sections
                if s["type"] == SHT_PROGBITS and s["flags"] & SHF_EXECINSTR and s["size"]]
        return sorted(secs, key=lambda s: s["addr"])

    def _sym_name(self, strtab_off: int, offset: int) -> str:
        start = strtab_off + offset
        if start >= len(self.data):
            return ""
        end = self.data.find(b"\x00", start)
        return self.data[start:end].decode("latin1", "replace")

    def got_slot(self, symname: str):
        """从 SHT_REL 里查 symname 的 GOT 槽虚拟地址。"""
        dynsym = next((s for s in self.sections
                       if s["type"] == SHT_DYNSYM and s["entsize"] == 16), None)
        strtab = next((s for s in self.sections
                       if s["type"] == SHT_STRTAB and s["off"] > 0 and s["size"] > 16), None)
        if not dynsym or not strtab:
            return None
        for sec in self.sections:
            if sec["type"] != SHT_REL or sec["entsize"] != 8 or sec["size"] == 0:
                continue
            for j in range(sec["size"] // 8):
                r_off, r_info = struct.unpack_from("<II", self.data, sec["off"] + j * 8)
                sym = r_info >> 8
                if not sym:
                    continue
                st_name, = struct.unpack_from("<I", self.data, dynsym["off"] + sym * 16)
                if self._sym_name(strtab["off"], st_name) == symname:
                    return r_off
        return None


# --------------------------------------------------------------------------- #
# i386
# --------------------------------------------------------------------------- #

def find_plt_stub(elf: Elf32, got_slot: int):
    """定位 `jmp DWORD PTR ds:<got_slot>` 形态的标准 PLT 桩。

    标准桩 16 字节：`ff 25 <got>` + `68 <reloc index>` + `e9 <rel32 to plt0>`。
    """
    pat = b"\xff\x25" + p32(got_slot)
    off = elf.data.find(pat)
    while off >= 0:
        tail = elf.data[off + 6:off + 16]
        if len(tail) == 10 and tail[0] == 0x68 and tail[5] == 0xE9:
            for sec in elf.code_sections():
                if sec["off"] <= off < sec["off"] + sec["size"]:
                    return off, sec["addr"] + (off - sec["off"])
        off = elf.data.find(pat, off + 1)
    return None


I386_RET0 = b"\x31\xc0\xc3" + b"\x90" * 13      # xor eax,eax ; ret ; nop×13


def _i386_call_sites(elf: Elf32, stub_va: int):
    """扫描所有 `call rel32` 指向 stub_va 的位置。"""
    sites = []
    for sec in elf.code_sections():
        d = elf.data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        for i in range(0, len(d) - 4, 1):
            if d[i] != 0xE8:
                continue
            rel, = struct.unpack_from("<i", d, i + 1)
            if (base + i + 5 + rel) & 0xFFFFFFFF == stub_va:
                sites.append(base + i)
    return sites


def _i386_entry_for(elf: Elf32, got_slot: int):
    """按 .plt 表结构（PLT0 后每项 16 字节、GOT 每项 +4）反推某个 GOT 槽的桩位置。

    桩被改写后 `ff 25` 形态就没了，靠表结构才能定位 —— 用于判断"是否已打补丁"。
    """
    for sec in elf.code_sections():
        d = elf.data[sec["off"]:sec["off"] + sec["size"]]
        if len(d) < 32 or d[:2] != b"\xff\x35" or d[6:8] != b"\xff\x25":
            continue
        got0, = struct.unpack_from("<I", d, 18)
        delta = (got_slot - got0)
        if delta < 0 or delta % 4:
            continue
        entry_va = sec["addr"] + 16 + 16 * (delta // 4)
        off = sec["off"] + (entry_va - sec["addr"])
        if 0 <= off < len(elf.data) - 16:
            return off, entry_va
    return None


# --------------------------------------------------------------------------- #
# ARM32 / AArch32
# --------------------------------------------------------------------------- #

def find_arm_plt_entry(elf: Elf32, got_slot: int):
    """定位 ARM32 的 PLT 项（12 字节）：

        add ip, pc, #imm12a      ; ip  = PC + imm12a
        add ip, ip, #imm12b      ; ip += imm12b          (= GOT 基址 - 表偏移)
        ldr pc, [ip, #imm12c]!   ; 跳 GOT 槽

    直接按语义算出每个 PLT 项的目标 GOT 地址，与重定位给的 r_offset 比对，
    因此不依赖 PLT 项顺序、不依赖固定步长。
    """
    for sec in elf.code_sections():
        d = elf.data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        for o in range(0, len(d) - 11, 4):
            w1, w2, w3 = struct.unpack_from("<III", d, o)
            if (w1 & 0xFFFFF000) != 0xE28FC000:      # add ip, pc, #imm12
                continue
            if (w2 & 0xFFFFF000) != 0xE28CC000:      # add ip, ip, #imm12
                continue
            if (w3 & 0xFFFFF000) != 0xE5BCF000:      # ldr pc, [ip, #imm12]!
                continue
            va = base + o
            target = (va + 8) + _arm_imm12(w1) + _arm_imm12(w2) + (w3 & 0xFFF)
            if target & 0xFFFFFFFF == got_slot:
                return sec["off"] + o, va
    return None


ARM_RET0 = b"\x00\x00\xa0\xe3" + b"\x1e\xff\x2f\xe1" + b"\x00\x00\xa0\xe1"
#           mov r0, #0             bx lr                mov r0, r0 (占位)


def _arm_call_sites(elf: Elf32, entry_va: int):
    """扫描 ARM 模式 BL / BLX imm 指向 entry_va 的位置（4 字节对齐，纯编码解析）。"""
    sites = []
    for sec in elf.code_sections():
        d = elf.data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        for i in range(0, len(d) - 3, 4):
            w, = struct.unpack_from("<I", d, i)
            if (w & 0x0F000000) == 0x0B000000:          # BL
                pass
            elif (w & 0xFE000000) == 0xFA000000:        # BLX imm
                pass
            else:
                continue
            imm = w & 0xFFFFFF
            if imm & 0x800000:
                imm -= 0x1000000
            if (base + i + 8 + (imm << 2)) & 0xFFFFFFFF == entry_va:
                sites.append(base + i)
    return sites


def _arm_plt_entries(elf: Elf32):
    """列出所有 `add ip,pc,#a / add ip,ip,#b / ldr pc,[ip,#c]!` 形态的 PLT 项 (va, got)。"""
    out = []
    for sec in elf.code_sections():
        d = elf.data[sec["off"]:sec["off"] + sec["size"]]
        base = sec["addr"]
        for o in range(0, len(d) - 11, 4):
            w1, w2, w3 = struct.unpack_from("<III", d, o)
            if (w1 & 0xFFFFF000) != 0xE28FC000:
                continue
            if (w2 & 0xFFFFF000) != 0xE28CC000:
                continue
            if (w3 & 0xFFFFF000) != 0xE5BCF000:
                continue
            va = base + o
            out.append((va, ((va + 8) + _arm_imm12(w1) + _arm_imm12(w2) + (w3 & 0xFFF)) & 0xFFFFFFFF))
    return out


def _arm_entry_for(elf: Elf32, got_slot: int):
    """按 ARM PLT 表规律（项长 12 字节、GOT 每项 +4）反推某个 GOT 槽的项位置。"""
    entries = _arm_plt_entries(elf)
    if not entries:
        return None
    base_va, base_got = min(entries, key=lambda e: e[0])
    delta = got_slot - base_got
    if delta < 0 or delta % 4:
        return None
    entry_va = base_va + 12 * (delta // 4)
    # 该位置必须落在表内、且与表首同相位（项长 12）
    if (entry_va - base_va) % 12:
        return None
    if not base_va <= entry_va <= max(v for v, _ in entries) + 12:
        return None
    for sec in elf.code_sections():
        if sec["addr"] <= entry_va < sec["addr"] + sec["size"]:
            off = sec["off"] + (entry_va - sec["addr"])
            if 0 <= off < len(elf.data) - 12:
                return off, entry_va
    return None


# --------------------------------------------------------------------------- #
# 统一入口
# --------------------------------------------------------------------------- #

def _resolve(data: bytes, name: str):
    """返回 (elf, got, file_off, vaddr, ret0, call_sites, already_patched)。"""
    elf = Elf32(data)
    got = elf.got_slot("memcmp")
    if got is None:
        raise ValueError(f"{name}: 重定位表里没有 memcmp")
    if elf.machine == EM_386:
        found = find_plt_stub(elf, got)
        if found is None:
            found = _i386_entry_for(elf, got)
            if found is None:
                raise ValueError(f"{name}: 未找到 memcmp 的 PLT 桩 (GOT=0x{got:x})")
        off, va = found
        ret0 = I386_RET0
        patched = data[off:off + 3] == ret0[:3]
        return elf, got, off, va, ret0, _i386_call_sites(elf, va), patched
    if elf.machine == EM_ARM:
        found = find_arm_plt_entry(elf, got)
        if found is None:
            found = _arm_entry_for(elf, got)
            if found is None:
                raise ValueError(f"{name}: 未找到 memcmp 的 ARM PLT 项 (GOT=0x{got:x})")
        off, va = found
        ret0 = ARM_RET0
        patched = data[off:off + 12] == ret0
        return elf, got, off, va, ret0, _arm_call_sites(elf, va), patched
    raise ValueError(f"{name}: 不支持的架构 (e_machine={elf.machine})")


def patch_loader_plt(data: bytes, name: str = "loader"):
    """把 memcmp 的 PLT 项改写成"直接返回 0"。返回 (新数据, 说明)。长度不变。"""
    elf, got, off, va, ret0, sites, patched = _resolve(data, name)
    if patched:
        return data, (f"{name}: [{elf.arch}] memcmp@plt @0x{va:x} 已是补丁状态，跳过")
    orig = data[off:off + len(ret0)]
    out = bytearray(data)
    out[off:off + len(ret0)] = ret0
    note = (f"{name}: [{elf.arch}] memcmp@plt @0x{va:x} (file 0x{off:x}, GOT 0x{got:x}, "
            f"调用点 {len(sites)}) {orig.hex()} -> {bytes(out[off:off+len(ret0)]).hex()}")
    return bytes(out), note


def audit(data: bytes, name: str = "loader"):
    """逆向体检：不解包 loader.7z 也能说清 memcmp 挡的是哪一处校验。"""
    lines = [f"[audit] {name}"]
    elf = Elf32(data)
    lines.append(f"  arch                : {elf.arch} (e_machine={elf.machine})")
    got = elf.got_slot("memcmp")
    lines.append(f"  memcmp GOT 槽       : {hex(got) if got else '<无 memcmp 重定位>'}")
    if got:
        lit = []
        i = data.find(p32(got))
        while i >= 0:
            lit.append(hex(i))
            i = data.find(p32(got), i + 1)
        lines.append(f"  文件内 GOT 字面量   : {', '.join(lit) or '无'}"
                     "   (只应出现在 PLT 桩操作数与 .rel.plt；否则说明有旁路调用)")
    try:
        _, _, off, va, ret0, sites, patched = _resolve(data, name)
    except ValueError as e:
        lines.append(f"  PLT 定位失败        : {e}")
        off = va = ret0 = None
        sites, patched = [], False
    if va is not None:
        lines.append(f"  memcmp@plt          : vaddr 0x{va:x} file 0x{off:x}")
        lines.append(f"  调用点 ({len(sites)})        : "
                     + (", ".join(hex(s) for s in sites) or "无"))
        cur = data[off:off + len(ret0)]
        lines.append(f"  PLT 状态            : "
                     f"{'已补丁' if patched else '原始'}  {cur.hex()}")
    lines.extend(_audit_license_key(data, elf.arch))
    return "\n".join(lines)


def _audit_license_key(data: bytes, arch: str = "i386"):
    out = []
    hits = []
    i = data.find(LICENSE_PUBKEY)
    while i >= 0:
        hits.append(i)
        i = data.find(LICENSE_PUBKEY, i + 1)
    if hits:
        out.append("  license 公钥布局    : 连续 32 字节 @ " + ", ".join(hex(h) for h in hits))
        return out
    # ≥7.18.2 起被打散成 x86 的 8 条 movl 立即数：
    #   6 × `c7 85 disp32 imm32`（10 字节， imm 在 +6）：store 0..5 位于 +0,+10,…,+50
    #   2 × `c7 45 disp8  imm32`（ 7 字节， imm 在 +3）：store 6 位于 +60，store 7 位于 +67
    for j in range(len(data) - 80):
        if data[j] == 0xC7 and data[j + 1] == 0x85:
            blob = b"".join(data[j + 6 + k * 10:j + 10 + k * 10] for k in range(6))
            if blob == LICENSE_PUBKEY[:24]:
                whole = blob + data[j + 63:j + 67] + data[j + 70:j + 74]
                tag = "官方" if whole == LICENSE_PUBKEY else "已被替换 (自定义/作者)"
                out.append(f"  license 公钥布局    : 打散 8×imm32 @ file 0x{j:x} ({tag})")
                return out
    # ARM literal pool 等：公钥按 32 位字内联，顺序不保证连续，用"命中了几个字"判断
    words = [LICENSE_PUBKEY[k * 4:k * 4 + 4] for k in range(8)]
    found = sum(1 for w in words if data.find(w) >= 0)
    if arch == "arm":
        out.append(f"  license 公钥布局    : ARM 内联字面量，{found}/8 个字命中"
                   + ("（官方）" if found >= 6 else "（未见官方公钥）"))
    else:
        # 注意：不是所有组件都内嵌 license 公钥（7.x 只有 mode/keyman/loader 有），
        # 所以 0 命中既可能是"已被替换"，也可能是"本来就没有" —— 与同版本官方件对比确认。
        out.append(f"  license 公钥布局    : 连续/imm32 两种布局都没命中（{found}/8 字残存）"
                   " → 已被替换，或本组件本来就不内嵌该公钥")
    return out


def patch_loader(data: bytes, name: str = "loader"):
    return patch_loader_plt(data, name)


def patch_loader_file(path: str):
    with open(path, "rb") as f:
        data = f.read()
    out, note = patch_loader(data, name=path)
    if out != data:
        with open(path, "wb") as f:
            f.write(out)
    print(note)
    return out


if __name__ == "__main__":
    args = sys.argv[1:]
    if args and args[0] == "--audit":
        for p in args[1:]:
            print(audit(open(p, "rb").read(), p))
    else:
        for p in args or ["nova/bin/loader"]:
            patch_loader_file(p)
