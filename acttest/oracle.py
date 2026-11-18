import os, sys, io, struct, zipfile, hashlib, base64, subprocess, random
sys.path.insert(0, r"G:\LogaToolChangerV2\samples")
import analyze_sample as az   # az.stream_xor(key, nonce, data, counter, layout)

ADB = r"C:\Users\NTH\AppData\Local\Android\Sdk\platform-tools\adb.exe"
SER = sys.argv[1] if len(sys.argv) > 1 else "RHXMANM59KU"
LOGA = r"G:\LogaToolChangerV2\roms\_rec_star2lte\logaapply.real"
TMP  = r"G:\LogaToolChangerV2\acttest\_cand"

def sh(args, inp=None):
    return subprocess.run([ADB, "-s", SER] + args, capture_output=True, text=True)

# --- plaintext: 1 file zip nhỏ ---
buf = io.BytesIO()
with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
    z.writestr("system_root/system/build.prop", "ro.product.model=TEST\n" * 3)
plain = buf.getvalue()

seed = bytes(range(32))        # seed cố định dễ nhận
salt = bytes([0x11]*16)        # salt cố định
A = hashlib.sha256(seed+salt).digest()
B = hashlib.sha256(salt+seed).digest()
def xr(a,b): return bytes(x^y for x,y in zip(a,b))

keys = {
 "A": A, "B": B, "A16B16": A[:16]+B[:16], "B16A16": B[:16]+A[:16],
 "AxorB": xr(A,B), "sha(seed)": hashlib.sha256(seed).digest(), "sha(salt)": hashlib.sha256(salt).digest(),
}
nonces = {
 "salt12": salt[:12], "salt8": salt[:8], "zero12": b"\0"*12, "zero8": b"\0"*8,
 "salt_4_16": salt[4:16], "salt_8_16": salt[8:16], "A12": A[:12], "B12": B[:12], "A8": A[:8], "B8": B[:8],
}

os.makedirs(TMP, exist_ok=True)
for f in os.listdir(TMP): os.remove(os.path.join(TMP, f))
meta = []
idx = 0
for kn, key in keys.items():
    for nn, nonce in nonces.items():
        for layout in ("ietf","djb"):
            if layout=="ietf" and len(nonce)!=12: continue
            if layout=="djb" and len(nonce)!=8: continue
            for ctr in (0,1):
                ct = az.stream_xor(key, nonce, plain, ctr, layout)
                bk = b"LGB1"+salt+ct
                fn = f"c{idx:03d}.bk"; idx+=1
                open(os.path.join(TMP, fn), "wb").write(bk)
                meta.append((fn, f"key={kn} nonce={nn} layout={layout} ctr={ctr}"))

print(f"generated {idx} candidates, plain_len={len(plain)}")

# --- push everything ---
sh(["shell","rm -rf /data/local/tmp/cand /data/local/tmp/logaapply /data/local/tmp/seed.b64 /data/local/tmp/out.zip"])
print(sh(["push", LOGA, "/data/local/tmp/logaapply"]).stdout.strip())
sh(["shell","chmod 755 /data/local/tmp/logaapply"])
open(os.path.join(TMP,"seed.b64"),"wb").write(base64.b64encode(seed))
print(sh(["push", TMP, "/data/local/tmp/cand"]).stdout.strip())

# sanity: run logaapply on first candidate, show rc + out magic
r = sh(["shell","/data/local/tmp/logaapply /data/local/tmp/cand/c000.bk /data/local/tmp/out.zip /data/local/tmp/cand/seed.b64; echo RC=$?; dd if=/data/local/tmp/out.zip bs=1 count=4 2>/dev/null | od -An -tx1; wc -c </data/local/tmp/out.zip 2>/dev/null"])
print("SANITY:", r.stdout, r.stderr)

# --- run all candidates on device ---
script = ("cd /data/local/tmp/cand; for f in c*.bk; do "
          "/data/local/tmp/logaapply \"$f\" /data/local/tmp/out.zip /data/local/tmp/cand/seed.b64 >/dev/null 2>&1; rc=$?; "
          "m=$(dd if=/data/local/tmp/out.zip bs=1 count=2 2>/dev/null); "
          "sz=$(wc -c </data/local/tmp/out.zip 2>/dev/null); "
          "if [ \"$m\" = \"PK\" ]; then echo \"HIT $f rc=$rc sz=$sz\"; fi; done; echo DONE")
res = sh(["shell", script])
print("RESULT:\n" + res.stdout + res.stderr)

hits = [l.split()[1] for l in res.stdout.splitlines() if l.startswith("HIT ")]
d = dict((m[0], m[1]) for m in meta)
for h in hits:
    print("MATCH:", h, "=>", d.get(h))
if not hits:
    print("Khong co candidate ChaCha nao dung. (co the la AES hoac cong thuc khac)")
print("PLAIN_LEN", len(plain))
