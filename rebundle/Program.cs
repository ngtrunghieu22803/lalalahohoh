using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using System.Reflection;

string bundlePath = @"G:\LogaToolChangerV2\LogaChanger.exe.orig";
string bakPath    = @"G:\LogaToolChangerV2\qua_trinh_giai\NativeS9Manager.dll.bak";
string patchedPath= @"G:\LogaToolChangerV2\qua_trinh_giai\NativeS9Manager.dll";
string outPath    = @"G:\LogaToolChangerV2\LogaChanger.local.exe";
foreach (var a in args) { if (!a.StartsWith("--") && a.EndsWith(".exe")) outPath = a; }

byte[] b = File.ReadAllBytes(bundlePath);
byte[] bak = File.ReadAllBytes(bakPath);
byte[] patched = File.ReadAllBytes(patchedPath);
Console.WriteLine($"bundle={b.Length} bak={bak.Length} patched={patched.Length}");

byte[] Inflate(byte[] data, int maxLen)
{
    using var ms = new MemoryStream(data);
    using var ds = new DeflateStream(ms, CompressionMode.Decompress);
    var buf = new byte[maxLen]; int total = 0, r;
    try { while (total < maxLen && (r = ds.Read(buf, total, maxLen - total)) > 0) total += r; } catch { }
    Array.Resize(ref buf, total); return buf;
}
byte[] Deflate(byte[] data, CompressionLevel lvl)
{
    using var ms = new MemoryStream();
    using (var ds = new DeflateStream(ms, lvl, leaveOpen: true)) ds.Write(data, 0, data.Length);
    return ms.ToArray();
}
long I64(byte[] a, long p) => BitConverter.ToInt64(a, (int)p);

List<Entry> ParseFrom(byte[] arr, long start)
{
    var list = new List<Entry>();
    long p = start;
    while (p < arr.Length)
    {
        if (p + 26 > arr.Length) throw new Exception("eob");
        long off = I64(arr, p); long unc = I64(arr, p + 8); long cmp = I64(arr, p + 16);
        byte type = arr[(int)(p + 24)]; int nl = arr[(int)(p + 25)];
        if (nl < 1 || nl > 300 || p + 26 + nl > arr.Length) throw new Exception("nl");
        if (off < 0 || off >= arr.Length || cmp < 0 || off + cmp > arr.Length) throw new Exception("range");
        for (int k = 0; k < nl; k++) { byte c = arr[(int)(p + 26 + k)]; if (c < 32 || c > 126) throw new Exception("nm"); }
        list.Add(new Entry(off, unc, cmp, type, Encoding.UTF8.GetString(arr, (int)(p + 26), nl), p));
        p += 26 + nl;
    }
    return list;
}

long Hent = -1; List<Entry> entries = null;
for (long P = Math.Max(0, b.Length - 400000); P < b.Length - 12; P++)
{
    try { var r = ParseFrom(b, P); if (r.Count >= 20 && r[r.Count-1].Name.Length>0) { entries = r; Hent = P; break; } } catch { }
}
if (entries == null) { Console.WriteLine("KHONG parse"); return; }
var dll = entries.FirstOrDefault(e => e.Name == "NativeS9Manager.dll");
var next = entries.Where(e => e.Offset > dll.Offset).OrderBy(e => e.Offset).First();
long slot = next.Offset - dll.Offset;
Console.WriteLine($"dll off=0x{dll.Offset:X} unc={dll.Uncomp} comp={dll.Comp} type={dll.Type}");
Console.WriteLine($"next off=0x{next.Offset:X} ({next.Name})  slot={slot}");

var c9 = Deflate(patched, CompressionLevel.Optimal);
var c9s = Deflate(patched, CompressionLevel.SmallestSize);
byte[] compPatch = c9.Length <= c9s.Length ? c9 : c9s;
string zbin = @"G:\LogaToolChangerV2\patched.zopfli.bin";
if (File.Exists(zbin))
{
    var z = File.ReadAllBytes(zbin);
    if (Inflate(z, patched.Length + 16).AsSpan().SequenceEqual(patched)) { compPatch = z; Console.WriteLine("dung zopfli bin"); }
    else Console.WriteLine("zopfli bin KHONG khop patched, bo qua");
}
Console.WriteLine($"deflate(patched): optimal={c9.Length} smallest={c9s.Length} zopfli={compPatch.Length}; fits slot? {compPatch.Length <= slot}");

if (compPatch.Length > slot) { Console.WriteLine("!! khong vua slot"); return; }

// in-place: copy, overwrite dll blob slot with compPatch + zero pad
var outb = (byte[])b.Clone();
Array.Clear(outb, (int)dll.Offset, (int)slot);
Array.Copy(compPatch, 0, outb, (int)dll.Offset, compPatch.Length);
// update dll entry fields: unc=patched.Length, comp=compPatch.Length (offset unchanged)
long ep = dll.HdrPos;
Array.Copy(BitConverter.GetBytes((long)patched.Length), 0, outb, (int)(ep + 8), 8);
Array.Copy(BitConverter.GetBytes((long)compPatch.Length), 0, outb, (int)(ep + 16), 8);
File.WriteAllBytes(outPath, outb);
Console.WriteLine($"WROTE {outPath} size={outb.Length}");

// verify: reparse output, decompress dll, load R/kU
var oe = ParseFrom(outb, Hent);
var odll = oe.First(e => e.Name == "NativeS9Manager.dll");
var ob = new byte[odll.Comp]; Array.Copy(outb, odll.Offset, ob, 0, odll.Comp);
var d = Inflate(ob, (int)(odll.Uncomp + 16));
Console.WriteLine($"verify: out dll inflate={d.Length} prefixEqPatched={d.Length >= patched.Length && d.AsSpan(0, patched.Length).SequenceEqual(patched)}");

var padded = new byte[d.Length]; Array.Copy(d, padded, d.Length);
string tmp = Path.Combine(Path.GetTempPath(), "ns9m_out.dll"); File.WriteAllBytes(tmp, padded);
try {
    AppDomain.CurrentDomain.AssemblyResolve += (s, e) => { var pth = Path.Combine(@"G:\LogaToolChangerV2\qua_trinh_giai", new AssemblyName(e.Name).Name + ".dll"); return File.Exists(pth) ? Assembly.LoadFrom(pth) : null; };
    var asm = Assembly.LoadFrom(tmp);
    string C0(string n){ var mi=asm.GetTypes().SelectMany(t=>t.GetMethods(BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic)).FirstOrDefault(m=>m.Name==n&&m.GetParameters().Length==0); return mi?.Invoke(null,null) as string ?? "(null)"; }
    Console.WriteLine("R()  = " + C0("R"));
    var ku=C0("kU"); Console.WriteLine("kU() = " + (ku.Length>20?ku[..20]+"...":ku) + $" (len {ku.Length})");
} catch(Exception e){ Console.WriteLine("[reflect] "+e.Message); }

record Entry(long Offset, long Uncomp, long Comp, byte Type, string Name, long HdrPos);
