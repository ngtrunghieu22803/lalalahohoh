import struct
from capstone import *

path = r"G:\LogaToolChangerV2\roms\_rec_star2lte\logaapply.real"
data = open(path, "rb").read()

# Parse ELF64 program headers
assert data[:4] == b"\x7fELF"
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i*e_phentsize
    p_type = struct.unpack_from("<I", data, off)[0]
    if p_type != 1:  # PT_LOAD
        continue
    p_offset = struct.unpack_from("<Q", data, off+0x08)[0]
    p_vaddr  = struct.unpack_from("<Q", data, off+0x10)[0]
    p_filesz = struct.unpack_from("<Q", data, off+0x20)[0]
    p_flags  = struct.unpack_from("<I", data, off+0x04)[0]
    segs.append((p_offset, p_vaddr, p_filesz, p_flags))

def off2va(o):
    for po, va, sz, fl in segs:
        if po <= o < po+sz: return va + (o-po)
    return None
def va2off(v):
    for po, va, sz, fl in segs:
        if va <= v < va+sz: return po + (v-va)
    return None

targets = {
    0x2675: "LGB1",
    0x1008: "expand32k",
    0x7362: "magic sai",
    0x7373: "decrypt err",
    0x13853: "usage",
    0x17401: "open seed fail",
    0x19860: "/data/vendor/hwcfg/seed",
}
tva = {off2va(o): n for o, n in targets.items()}
print("target vas:", {hex(k):v for k,v in tva.items()})

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

# quick sanity: disasm first 30 insns of first exec segment
for po, va, sz, fl in segs:
    if fl & 1:
        print("== sample exec seg va=%#x ==" % va)
        for k,ins in enumerate(md.disasm(data[po:po+240], va)):
            print(f"{ins.address:#010x}: {ins.mnemonic}\t{ins.op_str}")
            if k>25: break
        break

# disassemble all executable PT_LOAD segments and resolve adrp+{add,ldr}
xrefs = {}
for po, va, sz, fl in segs:
    if not (fl & 1):
        continue
    code = data[po:po+sz]
    adrp = {}
    for ins in md.disasm(code, va):
        m = ins.mnemonic
        ops = ins.operands
        if m == "adrp" and len(ops) == 2 and ops[1].type == CS_OP_IMM:
            dreg = md.reg_name(ops[0].reg)
            adrp[dreg] = ops[1].imm
        elif m == "add" and len(ops) == 3 and ops[2].type == CS_OP_IMM and ops[1].type == CS_OP_REG:
            base = md.reg_name(ops[1].reg)
            if base in adrp:
                tgt = adrp[base] + ops[2].imm
                if tgt in tva:
                    xrefs.setdefault(tva[tgt], []).append(ins.address)
        elif m in ("ldr","ldrb","ldrh","ldrsw") and len(ops) >= 2 and ops[1].type == CS_OP_MEM:
            mem = ops[1].mem
            base = md.reg_name(mem.base)
            if base in adrp:
                tgt = adrp[base] + mem.disp
                if tgt in tva:
                    xrefs.setdefault(tva[tgt], []).append(ins.address)
for name, addrs in xrefs.items():
    print(f"{name}: xref @ " + ", ".join(hex(a) for a in addrs))

# dump function window around 'magic sai' xref (main)
def dump(around_va, n=70):
    o = va2off(around_va)
    if o is None: 
        print("no off"); return
    start = max(0, around_va - 0) 
    code = data[o-o%4 - 4*n if o-4*n>=0 else 0: o+4*n]
    base = around_va - (around_va%4) - 4*n
    for ins in md.disasm(code, base):
        print(f"{ins.address:#010x}: {ins.mnemonic}\t{ins.op_str}")

if "magic sai" in xrefs:
    print("========== around 'magic sai' ==========")
    dump(xrefs["magic sai"][0], 90)
