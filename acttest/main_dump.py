import struct
from capstone import *

path = r"G:\LogaToolChangerV2\roms\_rec_star2lte\logaapply.real"
data = open(path, "rb").read()
e_phoff = struct.unpack_from("<Q", data, 0x20)[0]
e_phentsize = struct.unpack_from("<H", data, 0x36)[0]
e_phnum = struct.unpack_from("<H", data, 0x38)[0]
segs=[]
for i in range(e_phnum):
    off=e_phoff+i*e_phentsize
    if struct.unpack_from("<I",data,off)[0]!=1: continue
    segs.append((struct.unpack_from("<Q",data,off+0x08)[0],
                 struct.unpack_from("<Q",data,off+0x10)[0],
                 struct.unpack_from("<Q",data,off+0x20)[0],
                 struct.unpack_from("<I",data,off+0x04)[0]))
def va2off(v):
    for po,va,sz,fl in segs:
        if va<=v<va+sz: return po+(v-va)
    return None
def seg_of(v):
    for po,va,sz,fl in segs:
        if va<=v<va+sz: return po,va,sz
    return None

md=Cs(CS_ARCH_ARM64,CS_MODE_ARM); md.detail=True
lo,hi=0x2222c0,0x222fa0
so=va2off(lo)
code=data[so: so+(hi-lo)]

reg={}
def str_at(v):
    off=va2off(v)
    if off is None or off<0 or off>=len(data): return None
    blob=data[off:off+24]
    s="".join(chr(c) if 32<=c<127 else "." for c in blob)
    return s

for ins in md.disasm(code, lo):
    line=f"{ins.address:#010x}: {ins.mnemonic:<8}{ins.op_str}"
    m=ins.mnemonic; ops=ins.operands
    cm=""
    if m=="adrp" and len(ops)==2 and ops[1].type==CS_OP_IMM:
        reg[md.reg_name(ops[0].reg)]=ops[1].imm
    if m in ("cmp","mov","movz","movk","movn") and ops and ops[-1].type==CS_OP_IMM:
        cm=f"   ; imm={ops[-1].imm:#x}"
        if ins.address < 0: pass
    if m=="add" and len(ops)>=3 and ops[2].type==CS_OP_IMM:
        v=reg.get(md.reg_name(ops[1].reg)) if ops[1].type==CS_OP_REG else None
        sh=ops[3].imm if len(ops)==4 and ops[3].type==CS_OP_IMM else 0
        if v is not None:
            t=v+(ops[2].imm<<sh); reg[md.reg_name(ops[0].reg)]=t
            s=str_at(t)
            if s: cm=f"   ; ->{t:#x} {s!r}"
    if m=="ldr" and len(ops)==2 and ops[1].type==CS_OP_MEM:
        base=md.reg_name(ops[1].mem.base); v=reg.get(base)
        if v is not None:
            t=v+ops[1].mem.disp; s=str_at(t)
            if s: cm=f"   ; ->{t:#x} {s!r}"
    if m in ("bl","b") and ops and ops[0].type==CS_OP_IMM:
        cm=f"   ; target={ops[0].imm:#x}"
    print(line+cm)
