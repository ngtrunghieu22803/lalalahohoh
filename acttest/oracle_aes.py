import os, sys, io, zipfile, hashlib, base64, subprocess
from Crypto.Cipher import AES
from Crypto.Util import Counter as Ctr

ADB = r"C:\Users\NTH\AppData\Local\Android\Sdk\platform-tools\adb.exe"
SER = sys.argv[1] if len(sys.argv) > 1 else "RHXMANM59KU"
LOGA = r"G:\LogaToolChangerV2\roms\_rec_star2lte\logaapply.real"
TMP  = r"G:\LogaToolChangerV2\acttest\_cand"
def sh(a): return subprocess.run([ADB,"-s",SER]+a,capture_output=True,text=True)

# plaintext = zip, pad to 16-multiple
buf=io.BytesIO()
with zipfile.ZipFile(buf,"w",zipfile.ZIP_DEFLATED) as z:
    z.writestr("system_root/system/build.prop","ro.product.model=TEST\n"*3)
plain=buf.getvalue()
if len(plain)%16: plain=plain+b"\0"*(16-len(plain)%16)
print("plain_len(mult16)=",len(plain),"orig starts",plain[:4])

seed=bytes(range(32)); salt=bytes([0x11]*16)
A=hashlib.sha256(seed+salt).digest(); B=hashlib.sha256(salt+seed).digest()
def xr(a,b): return bytes(x^y for x,y in zip(a,b))
keys={
 "A":A,"B":B,"sha(seed)":hashlib.sha256(seed).digest(),"sha(salt)":hashlib.sha256(salt).digest(),
 "AxorB":xr(A,B),"A16B16":A[:16]+B[:16],"B16A16":B[:16]+A[:16],
 "A16":A[:16],"B16":B[:16],"shoe(seed16)":hashlib.sha256(seed).digest()[:16],"sha(salt16)":hashlib.sha256(salt).digest()[:16],
}
ivs={"salt":salt,"zero":b"\0"*16,"B16":B[:16],"A16":A[:16]}

os.makedirs(TMP,exist_ok=True)
for f in os.listdir(TMP): os.remove(os.path.join(TMP,f))
meta=[]; idx=0
def emit(ct,desc):
    global idx
    bk=b"LGB1"+salt+ct; fn=f"c{idx:03d}.bk"; idx+=1
    open(os.path.join(TMP,fn),"wb").write(bk); meta.append((fn,desc))

for kn,key in keys.items():
    klen=len(key)
    # CBC
    for ivn,iv in ivs.items():
        try: ct=AES.new(key,AES.MODE_CBC,iv).encrypt(plain); emit(ct,f"key={kn}({klen}) CBC iv={ivn}")
        except Exception as e: pass
    # ECB
    try: ct=AES.new(key,AES.MODE_ECB).encrypt(plain); emit(ct,f"key={kn}({klen}) ECB")
    except Exception: pass
    # CTR (full 16-byte counter=iv, big-endian)
    for ivn,iv in ivs.items():
        try:
            ctr=Ctr.new(128,initial_value=int.from_bytes(iv,"big"))
            ct=AES.new(key,AES.MODE_CTR,counter=ctr).encrypt(plain); emit(ct,f"key={kn}({klen}) CTR iv={ivn}")
        except Exception: pass
    # CFB / OFB
    for ivn,iv in ivs.items():
        for m,nm in ((AES.MODE_CFB,"CFB"),(AES.MODE_OFB,"OFB")):
            try: ct=AES.new(key,m,iv).encrypt(plain); emit(ct,f"key={kn}({klen}) {nm} iv={ivn}")
            except Exception: pass

print("candidates:",idx)
sh(["shell","rm -rf /data/local/tmp/cand /data/local/tmp/logaapply /data/local/tmp/out.zip"])
sh(["push",LOGA,"/data/local/tmp/logaapply"]); sh(["shell","chmod 755 /data/local/tmp/logaapply"])
open(os.path.join(TMP,"seed.b64"),"wb").write(base64.b64encode(seed))
sh(["push",TMP,"/data/local/tmp/cand"])
script=("cd /data/local/tmp/cand; for f in c*.bk; do "
 "/data/local/tmp/logaapply \"$f\" /data/local/tmp/out.zip /data/local/tmp/cand/seed.b64 >/dev/null 2>&1; "
 "m=$(dd if=/data/local/tmp/out.zip bs=1 count=2 2>/dev/null); sz=$(wc -c </data/local/tmp/out.zip 2>/dev/null); "
 "if [ \"$m\" = \"PK\" ]; then echo \"HIT $f $sz\"; fi; done; echo DONE")
res=sh(["shell",script]); print(res.stdout[-2000:], res.stderr)
d=dict(meta)
hits=[l.split() for l in res.stdout.splitlines() if l.startswith("HIT ")]
print("==== plain_len",len(plain))
for h in hits:
    fn=h[1]; sz=h[2]; print("MATCH",fn,"sz",sz,"=>",d.get(fn))
if not hits: print("No AES match yet.")
