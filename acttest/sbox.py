import struct
data=open(r"G:\LogaToolChangerV2\roms\_rec_star2lte\logaapply.real","rb").read()
# ELF map
e_phoff=struct.unpack_from("<Q",data,0x20)[0]; es=struct.unpack_from("<H",data,0x36)[0]; en=struct.unpack_from("<H",data,0x38)[0]
segs=[]
for i in range(en):
    o=e_phoff+i*es
    if struct.unpack_from("<I",data,o)[0]!=1: continue
    segs.append((struct.unpack_from("<Q",data,o+8)[0],struct.unpack_from("<Q",data,o+0x10)[0],struct.unpack_from("<Q",data,o+0x20)[0]))
def va2off(v):
    for po,va,sz in segs:
        if va<=v<va+sz: return po+(v-va)
    return None
def hexs(b): return " ".join(f"{x:02x}" for x in b)
for va in (0x205864,0x205a64,0x205864-0,0x205000+0xa64):
    o=va2off(va)
    if o is None: print(hex(va),"no"); continue
    b=data[o:o+32]
    print(hex(va),"off",hex(o),"->",hexs(b))
# AES sbox start for compare
aes=[0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76]
print("AES sbox   ->"," ".join(f'{x:02x}' for x in aes))
