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

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

def va2off(v):
    for po, va, sz, fl in segs:
        if va <= v < va+sz: return po + (v-va)
    return None

out = []
for po, va, sz, fl in segs:
    if not (fl & 1): continue
    code = data[po:po+sz]
    adrp = {}
    for ins in md.disasm(code, va):
        line = f"{ins.address:#010x}: {ins.mnemonic}\t{ins.op_str}"
        m = ins.mnemonic; ops = ins.operands
        if m == "adrp" and len(ops) == 2 and ops[1].type == CS_OP_IMM:
            dreg = md.reg_name(ops[0].reg); adrp[dreg] = ops[1].imm
        if m in ("add","ldr","ldrb","ldrh","ldrsw","ldrsh","str","strb","strh","cbz","cbnz","cmp") and len(ops) >= 2:
            # resolve if a source/base reg has adrp page and an imm offset
            for oi in range(len(ops)):
                op = ops[oi]
                base = None; disp = None
                if op.type == CS_OP_MEM:
                    base = md.reg_name(op.mem.base); disp = op.mem.disp
                elif op.type == CS_OP_IMM and oi+1 < len(ops) and ops[oi-1].type == CS_OP_REG:
                    base = md.reg_name(ops[oi-1].reg); disp = op.imm
                if base in adrp and disp is not None:
                    tgt = adrp[base] + disp
                    off = va2off(tgt)
                    if off is not None:
                        blob = data[off:off+12]
                        txt = "".join(chr(c) if 32<=c<127 else "." for c in blob)
                        line += f"   ; ->{tgt:#x} {txt!r}"
        out.append(line)

open(r"G:\LogaToolChangerV2\acttest\asm_all.txt","w",encoding="utf-8").write("\n".join(out))
print("instructions:", len(out))
