#!/usr/bin/env python3
"""
loader_dynamic.py -- RouterOS v7 x86 loader 的 license 校验链动态验证工具。

为什么需要它
------------
loader 里的 license 校验函数（i386 7.24.4 = 0x804f2d6）只有 838 字节，
但调用它的那个函数有 8128 字节：Ghidra 反编译直接超时，纯静态读汇编又会
在编译器优化的栈别名上踩坑（Ghidra 就把状态数组基址标偏了 4 字节）。
本工具改用 Unicorn 定点仿真，让真实指令流自己说话：

  * 校验函数本身：读什么、写什么、memcmp 比较什么、返回什么；
  * 调用方片段：拿到校验结果后，license level 究竟写进哪个字段，
    以及中途走了哪条分支；
  * patch 效果：只 stub memcmp、还是连校验函数一起 stub，行为差在哪。

地址全部自动推导（ELF 段 -> .rel.plt 找 memcmp -> PLT 桩 -> 调用点 ->
函数入口 -> 调用方栈偏移），不依赖符号表，也不依赖任何反编译器。

用法
----
  python3 tools/loader_dynamic.py nova/bin/loader --audit
  python3 tools/loader_dynamic.py nova/bin/loader --verify <64hex> [--patch memcmp]
  python3 tools/loader_dynamic.py nova/bin/loader --caller [--patch both]

依赖 pyelftools / capstone / unicorn。当前只覆盖 i386。
"""

from __future__ import annotations

import argparse
import os
import struct
import sys

from elftools.elf.elffile import ELFFile

try:
    import capstone
    from capstone import x86 as cs_x86
except ImportError:  # pragma: no cover
    sys.exit("需要 capstone: pip install capstone")

try:
    from unicorn import (
        Uc, UcError, UC_ARCH_X86, UC_HOOK_CODE, UC_MODE_32, UC_PROT_ALL,
    )
    from unicorn.x86_const import (
        UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_ECX,
        UC_X86_REG_EDX, UC_X86_REG_EIP, UC_X86_REG_ESP,
    )
except ImportError:  # pragma: no cover
    sys.exit("需要 unicorn: pip install unicorn")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from loader_patch import _resolve  # noqa: E402  复用既有的 ELF/PLT 解析

EM_386 = 3
STACK_VA = 0x70000000
STACK_SZ = 0x40000
SCRATCH_VA = 0x80000000
SCRATCH_SZ = 0x4000
SENTINEL = 0xDEADBEEF
BLOB_VA = SCRATCH_VA + 0x1000
OUT_VA = SCRATCH_VA + 0x2000
OBJ_VA = SCRATCH_VA + 0x3000

MEMCMP_STUB = b"\x31\xc0\xc3" + b"\x90" * 13   # xor eax,eax; ret
VERIFY_STUB = b"\xb8\x01\x00\x00\x00\xc3" + b"\x90"  # mov eax,1; ret


# --------------------------------------------------------------------------
# 静态定位
# --------------------------------------------------------------------------

def _section(elf, name):
    for sec in elf.iter_sections():
        if sec.name == name:
            return sec
    return None


def _disasm(data, elf):
    sec = _section(elf, ".text")
    if sec is None:
        raise SystemExit("找不到 .text")
    base = sec["sh_addr"]
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
    md.detail = True                      # 读操作数必须开
    instrs = {}
    for insn in md.disasm(data[sec["sh_offset"]: sec["sh_offset"] + sec["sh_size"]], base):
        instrs[insn.address] = insn
    return md, instrs, sorted(instrs)


def _imm(insn):
    for op in insn.operands:
        if op.type == cs_x86.X86_OP_IMM:
            return op.imm
    return None


def _ebp_disp(insn):
    for op in insn.operands:
        if op.type == cs_x86.X86_OP_MEM and op.mem.base == cs_x86.X86_REG_EBP:
            return op.mem.disp
    return None


def find_verify_fn(instrs, addrs, callsite):
    """从 memcmp 调用点向上找最近的函数入口（以 ret / int3 / 多字节 nop 为界）。"""
    idx = addrs.index(callsite)
    for i in range(idx - 1, -1, -1):
        insn = instrs[addrs[i]]
        if insn.mnemonic in ("ret", "retf", "int3") or (
                insn.mnemonic == "nop" and insn.size > 1):
            nxt = i + 1
            return addrs[nxt] if nxt < len(addrs) else None
    return None


def caller_fragment(instrs, addrs, callsite, plt, verify):
    """提取调用方片段：栈偏移、hash 调用点、区间端点、level 字段偏移。"""
    idx = addrs.index(callsite)
    res = {"callsite": callsite}

    # 1) 校验调用的两个 regparm 参数：edx = param_2(out)，eax = param_1(blob)
    for i in range(idx - 1, max(-1, idx - 8), -1):
        insn = instrs[addrs[i]]
        if insn.mnemonic != "lea":
            continue
        d = _ebp_disp(insn)
        if d is None:
            continue
        dst = insn.op_str.split(",")[0].strip()
        if dst == "edx" and "out" not in res:
            res["out"] = -d
        elif dst == "eax" and "blob" not in res:
            res["blob"] = -d
        if "out" in res and "blob" in res:
            break
    if "out" not in res or "blob" not in res:
        return None

    # 2) 向前找 hash 调用（非 plt、非 verify）
    hash_call = None
    for i in range(idx - 1, max(-1, idx - 80), -1):
        insn = instrs[addrs[i]]
        if insn.mnemonic == "call":
            t = _imm(insn)
            if t not in (plt, verify):
                hash_call = addrs[i]
                break
    if hash_call is None:
        return None
    res["hash_call"] = hash_call

    # 3) hash 的 edx = 第二段输入（DMI uuid 区），eax = 输出缓冲
    hi = addrs.index(hash_call)
    for i in range(hi - 1, max(-1, hi - 8), -1):
        insn = instrs[addrs[i]]
        if insn.mnemonic != "lea":
            continue
        d = _ebp_disp(insn)
        if d is None:
            continue
        dst = insn.op_str.split(",")[0].strip()
        if dst == "edx" and "dmi" not in res:
            res["dmi"] = -d
        elif dst == "eax" and "hash_out" not in res:
            res["hash_out"] = -d

    # 4) 片段起点：hash 调用之前最近的 mov ecx, imm32（哈希长度）
    start = None
    for i in range(hi - 1, max(-1, hi - 16), -1):
        insn = instrs[addrs[i]]
        if insn.mnemonic == "mov" and insn.op_str.startswith("ecx, ") \
                and "ptr" not in insn.op_str:
            start = addrs[i]
            break
    res["start"] = start or hash_call
    if "dmi" not in res:
        return None

    # 5) 向后：obj 指针槽、level = out[12]、写入字段偏移、片段终点
    for i in range(idx + 1, min(len(addrs), idx + 80)):
        insn = instrs[addrs[i]]
        mn, op = insn.mnemonic, insn.op_str
        if mn == "cmp" and op.startswith("dword ptr [ebp") and "obj_slot" not in res:
            d = _ebp_disp(insn)
            if d is not None:
                res["obj_slot"] = -d
        if mn == "movzx" and op.startswith("ecx, byte ptr [ebp") and "level_out_off" not in res:
            d = _ebp_disp(insn)
            if d is not None:
                # [ebp - N] 相对 out 基址的字节偏移：out - N
                res["level_out_off"] = res["out"] + d
        if mn == "mov" and op.startswith("dword ptr [") and op.rstrip().endswith("]") is False:
            try:
                off = int(op[op.rindex("+") + 1:op.index("]")], 16)
            except ValueError:
                off = None
            if off and "level_field" not in res and "+ 0x" in op:
                res["level_field"] = off
        if mn == "mov" and op.startswith("dword ptr [") and op.endswith(", 0"):
            res["end"] = addrs[i] + insn.size
            break
    for key in ("obj_slot", "level_field", "level_out_off", "end"):
        if key not in res:
            return None
    return res


def locate(path):
    with open(path, "rb") as fh:
        data = fh.read()
        elf = ELFFile(fh)
        info = _resolve(data, os.path.basename(path))
        if info is None:
            raise SystemExit("无法解析 memcmp 定位（该组件可能未引用 memcmp）")
        elf32, got, off, plt, ret0, sites, patched = info
        if elf32.machine != EM_386:
            raise SystemExit("本工具目前只支持 i386（machine=%s）" % elf32.machine)
        if not sites:
            raise SystemExit("未找到 memcmp 调用点")
        callsite = sites[0]
        md, instrs, addrs = _disasm(data, elf)
        # 先把段信息落成普通数据，后续仿真不再依赖 ELFFile（句柄会随 with 关闭）
        segs = [(s["p_vaddr"], s["p_offset"], s["p_filesz"], s["p_memsz"])
                for s in elf.iter_segments() if s["p_type"] == "PT_LOAD"]
        verify = find_verify_fn(instrs, addrs, callsite)
        if verify is None:
            raise SystemExit("无法从调用点 0x%x 反推校验函数入口" % callsite)
        # 调用方不是 memcmp 的调用点，而是"调用校验函数"的那一处
        vsites = [a for a in addrs
                  if instrs[a].mnemonic == "call" and _imm(instrs[a]) == verify]
        if not vsites:
            raise SystemExit("未找到对校验函数 0x%x 的调用点" % verify)
        vcall = vsites[-1]
        frag = caller_fragment(instrs, addrs, vcall, plt, verify)
        return {
            "data": data, "segs": segs, "plt": plt, "got": got,
            "callsites": sites, "callsite": callsite, "verify": verify,
            "vsites": vsites, "vcall": vcall,
            "frag": frag, "instrs": instrs, "addrs": addrs, "md": md,
        }


# --------------------------------------------------------------------------
# 仿真
# --------------------------------------------------------------------------

def _machine(loc, patch):
    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    # 先把各 PT_LOAD 的页区间合并，避免相邻段落在同一页时重复 mem_map
    regions = []
    for vaddr, poff, filesz, memsz in loc["segs"]:
        regions.append((vaddr & 0xFFFFF000, (vaddr + memsz + 0xFFF) & 0xFFFFF000))
    merged = []
    for lo, hi in sorted(regions):
        if merged and lo <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
        else:
            merged.append((lo, hi))
    for lo, hi in merged:
        mu.mem_map(lo, hi - lo, UC_PROT_ALL)
    for vaddr, poff, filesz, memsz in loc["segs"]:
        mu.mem_write(vaddr, loc["data"][poff: poff + filesz])
    mu.mem_map(STACK_VA, STACK_SZ, UC_PROT_ALL)
    mu.mem_map(SCRATCH_VA, SCRATCH_SZ, UC_PROT_ALL)
    if patch in ("memcmp", "both"):
        mu.mem_write(loc["plt"], MEMCMP_STUB)
    if patch == "both":
        mu.mem_write(loc["verify"], VERIFY_STUB)
    return mu


def _hook_memcmp(mu, loc, patch, sink):
    plt = loc["plt"]

    def hook(uc, addr, size, ud):
        if addr != plt or patch in ("memcmp", "both"):
            return
        sp = uc.reg_read(UC_X86_REG_ESP)
        a = struct.unpack("<I", bytes(uc.mem_read(sp + 4, 4)))[0]
        b = struct.unpack("<I", bytes(uc.mem_read(sp + 8, 4)))[0]
        n = struct.unpack("<I", bytes(uc.mem_read(sp + 12, 4)))[0]
        ba = bytes(uc.mem_read(a, n))
        bb = bytes(uc.mem_read(b, n))
        sink["memcmp"] = (ba.hex(), bb.hex(), ba == bb)
        ret = struct.unpack("<I", bytes(uc.mem_read(sp, 4)))[0]
        uc.reg_write(UC_X86_REG_ESP, sp + 4)
        uc.reg_write(UC_X86_REG_EAX, 0 if ba == bb else 1)
        uc.reg_write(UC_X86_REG_EIP, ret)

    mu.hook_add(UC_HOOK_CODE, hook)


def do_verify(loc, blob, patch):
    mu = _machine(loc, patch)
    mu.mem_write(BLOB_VA, blob)
    esp = STACK_VA + STACK_SZ - 0x1000
    mu.mem_write(esp, struct.pack("<I", SENTINEL))
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, esp)
    mu.reg_write(UC_X86_REG_EAX, BLOB_VA)   # param_1（regparm 传入）
    mu.reg_write(UC_X86_REG_EDX, OUT_VA)    # param_2
    sink = {}
    _hook_memcmp(mu, loc, patch, sink)
    try:
        mu.emu_start(loc["verify"], SENTINEL, count=200_000_000)
        ret = mu.reg_read(UC_X86_REG_EAX)
    except UcError as exc:
        return None, None, sink, str(exc)
    return ret, bytes(mu.mem_read(OUT_VA, 16)), sink, None


def do_caller(loc, dmi16, lic16, blob32, patch):
    frag = loc["frag"]
    if frag is None:
        raise SystemExit("调用方栈偏移自动提取失败，请先跑 --audit 核对")
    mu = _machine(loc, patch)
    ebp = STACK_VA + 0x20000
    mu.mem_write(ebp - frag["obj_slot"], struct.pack("<I", OBJ_VA))
    mu.mem_write(ebp - frag["dmi"], dmi16)
    mu.mem_write(ebp - frag["blob"] - 0x10, lic16)   # license 头部在 blob 之前 16 字节
    mu.mem_write(ebp - frag["blob"], blob32)         # param_1 = license[16..]

    esp = ebp - 0x1400
    mu.mem_write(esp, struct.pack("<I", SENTINEL))
    mu.reg_write(UC_X86_REG_ESP, esp)
    mu.reg_write(UC_X86_REG_EBP, ebp)

    path = []
    hi, cs = frag["end"], loc["vcall"]

    def hook(uc, addr, size, ud):
        if cs <= addr <= hi:
            path.append(addr)

    mu.hook_add(UC_HOOK_CODE, hook)
    _hook_memcmp(mu, loc, patch, {})  # 只需要拦截，不需要收集结果

    try:
        mu.emu_start(frag["start"], hi, count=200_000_000)
    except UcError as exc:
        return None, None, [hex(a) for a in path], str(exc)
    level = struct.unpack("<I", bytes(mu.mem_read(OBJ_VA + frag["level_field"], 4)))[0]
    out = bytes(mu.mem_read(ebp - frag["out"], 16))
    return level, out, [hex(a) for a in path], None


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

DEMO_DMI = bytes.fromhex("03000200040005000006000700080009")
DEMO_LIC16 = bytes(16)
DEMO_BLOB = (bytes.fromhex("3d867f1301000000") + bytes([6, 6]) + bytes(8)
             + bytes.fromhex("b34fe40e23f19e917107c449ddcb1d20"))


def main(argv=None):
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("loader")
    ap.add_argument("--audit", action="store_true", help="只打印自动定位结果")
    ap.add_argument("--verify", metavar="HEX64", help="仿真校验函数（32 字节输入）")
    ap.add_argument("--caller", action="store_true", help="仿真调用方片段")
    ap.add_argument("--patch", choices=["none", "memcmp", "both"], default="none",
                    help="memcmp=只把 memcmp@plt 换成 xor eax,eax;ret；"
                         "both=再把校验函数整体 stub")
    ap.add_argument("--dmi", default=DEMO_DMI.hex(), help="DMI product_uuid 16 字节")
    ap.add_argument("--lic16", default=DEMO_LIC16.hex(), help="license 头 16 字节")
    ap.add_argument("--blob", default=DEMO_BLOB.hex(), help="license[16..48]")
    args = ap.parse_args(argv)

    loc = locate(args.loader)
    frag = loc["frag"] or {}

    if args.audit:
        print("loader        : %s" % args.loader)
        print("arch          : i386")
        print("memcmp@plt    : 0x%x   GOT 0x%x" % (loc["plt"], loc["got"]))
        print("调用点        : %s" % ", ".join("0x%x" % s for s in loc["callsites"]))
        print("校验函数入口  : 0x%x" % loc["verify"])
        print("校验调用点    : %s" % ", ".join("0x%x" % s for s in loc["vsites"]))
        if frag:
            print("hash 调用     : 0x%x   片段 0x%x -> 0x%x"
                  % (frag["hash_call"], frag["start"], frag["end"]))
            print("栈偏移        : out=-0x%x blob=-0x%x dmi=-0x%x obj=-0x%x"
                  % (frag["out"], frag["blob"], frag["dmi"], frag["obj_slot"]))
            print("level         : out[%d] -> 对象 +0x%x"
                  % (frag["level_out_off"], frag["level_field"]))
        else:
            print("调用方栈偏移  : 自动提取失败")
        return 0

    if args.verify:
        blob = bytes.fromhex(args.verify)
        if len(blob) != 32:
            raise SystemExit("--verify 需要 32 字节（64 hex）")
        ret, out, sink, err = do_verify(loc, blob, args.patch)
        if err:
            raise SystemExit("仿真失败：%s" % err)
        print("patch         : %s" % args.patch)
        print("返回值 eax    : %d (%s)" % (ret, "通过" if ret else "失败"))
        print("out[0..16]    : %s" % out.hex())
        print("out[12]       : 0x%02x" % out[12])
        if sink.get("memcmp"):
            a, b, eq = sink["memcmp"]
            print("memcmp a      : %s" % a)
            print("memcmp b      : %s" % b)
            print("两侧相等      : %s" % eq)
        return 0

    if args.caller:
        dmi, lic = bytes.fromhex(args.dmi), bytes.fromhex(args.lic16)
        blob = bytes.fromhex(args.blob)
        if len(dmi) != 16 or len(lic) != 16 or len(blob) < 32:
            raise SystemExit("--dmi/--lic16 需 16 字节，--blob 至少 32 字节")
        level, out, path, err = do_caller(loc, dmi, lic, blob, args.patch)
        if err:
            raise SystemExit("仿真失败：%s" % err)
        print("patch         : %s" % args.patch)
        print("license level : 0x%x (%s)"
              % (level, "已保留" if level else "被清零"))
        print("调用后 out    : %s" % out.hex())
        print("分支路径      : %s" % (" ".join(path) if path else "-"))
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
