import sys, os, io, struct, zipfile, zlib, hashlib, base64, itertools

SAMP = r"G:\LogaToolChangerV2\samples\logaid.backup"
SEED = r"G:\LogaToolChangerV2\samples\seed.b64"

# ---------- ChaCha20 (pure python) ----------
def rotl(x, n): return ((x << n) | (x >> (32-n))) & 0xffffffff
def qr(s,a,b,c,d):
    s[a]=(s[a]+s[b])&0xffffffff; s[d]^=s[a]; s[d]=rotl(s[d],16)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]^=s[c]; s[b]=rotl(s[b],12)
    s[a]=(s[a]+s[b])&0xffffffff; s[d]^=s[a]; s[d]=rotl(s[d],8)
    s[c]=(s[c]+s[d])&0xffffffff; s[b]^=s[c]; s[b]=rotl(s[b],7)
def block(key, counter, nonce, layout):
    c=b"expand 32-byte k"
    kw=list(struct.unpack("<8I",key))
    if layout=="ietf":
        n=list(struct.unpack("<3I",nonce))
        st=[c[0:4],c[4:8],c[8:12],c[12:16]]
        st=[int.from_bytes(x,"little") for x in st]+kw+[counter&0xffffffff]+n
    else: # djb: 64-bit counter + 8-byte nonce
        n=list(struct.unpack("<2I",nonce))
        st=[int.from_bytes(c[0:4],"little"),int.from_bytes(c[4:8],"little"),
            int.from_bytes(c[8:12],"little"),int.from_bytes(c[12:16],"little")]+kw+[counter&0xffffffff,(counter>>32)&0xffffffff]+n
    x=st[:]
    for _ in range(10):
        qr(x,0,4,8,12); qr(x,1,5,9,13); qr(x,2,6,10,14); qr(x,3,7,11,15)
        qr(x,0,5,10,15); qr(x,1,6,11,12); qr(x,2,7,8,13); qr(x,3,4,9,14)
    out=struct.pack("<16I",*[ (x[i]+st[i])&0xffffffff for i in range(16)])
    return out
def stream_xor(key, nonce, data, counter0, layout):
    out=bytearray(); ctr=counter0; i=0
    while i < len(data):
        ks=block(key,ctr,nonce,layout); n=min(64,len(data)-i)
        for j in range(n): out.append(data[i+j]^ks[j])
        i+=n; ctr+=1
    return bytes(out)

def looks_like_zip(b):
    if b[:4]==b"PK\x03\x04" or b[:4]==b"PK\x05\x06": return True
    try:
        zipfile.ZipFile(io.BytesIO(b)).namelist(); return True
    except Exception: return False

def try_decode(tag, key, nonce, ct, counter, layout):
    if key is None or nonce is None: return None
    try:
        pt=stream_xor(key, nonce, ct, counter, layout)
    except Exception: return None
    variants=[]
    variants.append(("raw",pt))
    try: variants.append(("zlib",zlib.decompress(pt)))
    except Exception: pass
    try: variants.append(("zlib-raw",zlib.decompress(pt,-15)))
    except Exception: pass
    for vname,v in variants:
        if looks_like_zip(v):
            return f"{tag} layout={layout} counter={counter} {vname} -> ZIP OK  len={len(v)} first={v[:4]}"
    return None

def b64_any(s):
    s="".join(ch for ch in s if ch.isalnum() or ch in "+/=")
    return base64.b64decode(s + "="*(-len(s)%4))

def main():
    if not (os.path.exists(SAMP) and os.path.exists(SEED)):
        print("Thieu file. Can:"); print(" ", SAMP); print(" ", SEED); return
    data=open(SAMP,"rb").read()
    seed_txt=open(SEED,"rb").read()
    print("backup len=",len(data)," magic=",data[:4])
    if data[:4]!=b"LGB1":
        print("!! magic KHONG phai LGB1 -> sample nay ko dung (co the da bi ghi de)"); return
    salt=data[4:20]
    seed=b64_any(seed_txt if isinstance(seed_txt,str) else seed_txt.decode("latin1"))
    print("salt=",salt.hex()," seed_raw_len=",len(seed))
    A=hashlib.sha256(seed+salt).digest()
    B=hashlib.sha256(salt+seed).digest()
    C=hashlib.sha256(seed).digest()
    D=hashlib.sha256(salt).digest()
    print("A=SHA256(seed|salt)=",A.hex()[:16],".. B=SHA256(salt|seed)=",B.hex()[:16],"..")

    bodies = {"ct=data[20:]":data[20:]}
    if len(data)>36: bodies["ct_no_tag"]=data[20:-16]

    key_cands={
        "A":A, "B":B, "A[:16]+B[:16]":A[:16]+B[:16], "B[:16]+A[:16]":B[:16]+A[:16],
        "A[:16]+A[16:32]":A, "C":C, "D":D, "C[:16]+D[:16]":C[:16]+D[:16],
        "A[:16]x2":A[:16]+A[:16], "B[:16]x2":B[:16]+B[:16],
    }
    nonce_cands={
        "salt[:12]":salt[:12], "salt[:8]":salt[:8], "salt[8:16]":salt[8:16],
        "salt[4:12]":salt[4:12], "zero12":b"\0"*12, "zero8":b"\0"*8,
        "A[:12]":A[:12], "B[:12]":B[:12], "A[:8]":A[:8], "B[:8]":B[:8],
        "salt[4:16]":salt[4:16],
    }
    hits=[]
    for bname,ct in bodies.items():
        for kname,key in key_cands.items():
            for nname,nonce in nonce_cands.items():
                for layout in ("ietf","djb"):
                    if layout=="ietf" and len(nonce)!=12: continue
                    if layout=="djb" and len(nonce)!=8: continue
                    for counter in (0,1):
                        r=try_decode(f"{bname} key={kname} nonce={nname}",key,nonce,ct,counter,layout)
                        if r: hits.append(r); print("HIT:",r)
    print("\n==== tong hits:",len(hits),"====")
    if not hits:
        print("Chua khop cong thuc. Gui minh file nay, minh mo rong them (ChaCha20-Poly1305 / key tu xor / counter tu salt...).")

if __name__=="__main__": main()
