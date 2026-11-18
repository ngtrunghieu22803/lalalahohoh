import struct
from capstone import *

path = r"G:\LogaToolChangerV2\roms\_rec_star2lte\logaapply.real"
data = open(path, "rb").read()
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
segs = []
for i in range(e_phnum):
    off = e_phoff + i*e_phentsize
    if struct.unpack_from("<I", data, off)[0] != 1: continue
    p_offset = struct.unpack_from("<Q", data, off+0x08)[0]
    p_vaddr  = struct.unpack_from("<Q", data, off+0x10)[0]
    p_filesz = struct.unpack_from("<Q", data, off+0x20)[0]
    p_flags  = struct.unpack_from("<I", data, off+0x04)[0]
    segs.append((p_offset, p_vaddr, p_filesz, p_flags))

def va2off(v):
    for po, va, sz, fl in segs:
        if va <= v < va+sz: return po + (v-va)
    return None

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM); md.detail = True
KW = ["magic","LGB","expand 32-byte","/data/vendor/hwcfg/seed","decrypt err","usage: logaapply","open seed","backup ng","CHECK"]

hits = []
for po, va, sz, fl in segs:
    if not (fl & 1): continue
    code = data[po:po+sz]
    reg = {}  # regname -> int val
    for ins in md.disasm(code, va):
        m = ins.mnemonic; ops = ins.operands
        def rv(idx):
            try:
                if ops[idx].type == CS_OP_REG: return reg.get(md.reg_name(ops[idx].reg))
            except Exception: return None
            return None
        if m == "adrp" and len(ops)==2 and ops[1].type==CS_OP_IMM:
            reg[md.reg_name(ops[0].reg)] = ops[1].imm
        elif m == "add" and len(ops)==4 and ops[2].type==CS_OP_IMM and ops[3].type==CS_OP_IMM:
            v = rv(1)
            if v is not None:
                reg[md.reg_name(ops[0].reg)] = v + (ops[2].imm << ops[3].imm)
        elif m == "add" and len(ops)==3 and ops[2].type==CS_OP_IMM:
            v = rv(1)
            if v is not None:
                reg[md.reg_name(ops[0].reg)] = v + ops[2].imm
        elif m == "mov" and len(ops)==2 and ops[1].type==CS_OP_REG:
            reg[md.reg_name(ops[0].reg)] = rv(1)
        elif m == "ldr" and len(ops)==2 and ops[1].type==CS_OP_MEM:
            base = md.reg_name(ops[1].mem.base); v = reg.get(base)
            if v is not None:
                tgt = v + ops[1].mem.disp
                off = va2off(tgt)
                if off:
                    blob = data[off:off+16]
                    s = "".join(chr(c) if 32<=c<127 else "." for c in blob)
                    if any(k in s for k in KW):
                        hits.append((ins.address, tgt, s))
                    # loaded pointer unknown now
                    reg[md.reg_name(ops[0].reg)] = None
        # any add result pointing at string
        d = md.reg_name(ops[0].reg) if ops and ops[0].type==CS_OP_REG and m in ("add","mov") else None
        if d and d in reg and reg[d] is not None:
            off = va2off(reg[d])
            if off:
                blob = data[off:off+16]; s="".join(chr(c) if 32<=c<127 else "." for c in blob)
                if any(k in s for k in KW):
                    hits.append((ins.address, reg[d], s))

seen=set(); 
for a,t,s in hits:
    key=(a,t)
    if key in seen: continue
    seen.add(key)
    print(f"{a:#x} -> {t:#x}  {s!r}")
print("hits:", len(seen))
