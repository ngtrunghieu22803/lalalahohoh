using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

string bundlePath = args.Length > 0 ? args[0] : @"G:\LogaToolChangerV2\LogaChanger.exe.orig";
string bakPath    = args.Length > 1 ? args[1] : @"G:\LogaToolChangerV2\qua_trinh_giai\NativeS9Manager.dll.bak";
string patchedPath= args.Length > 2 ? args[2] : @"G:\LogaToolChangerV2\qua_trinh_giai\NativeS9Manager.dll";
string outPath    = args.Length > 3 ? args[3] : @"G:\LogaToolChangerV2\LogaChanger.local.exe";
long knownOff     = 0xD36BA4;

byte[] bundle = File.ReadAllBytes(bundlePath);
byte[] bak = File.ReadAllBytes(bakPath);
byte[] patched = File.ReadAllBytes(patchedPath);
Console.WriteLine($"bundle={bundle.Length} bak={bak.Length} patched={patched.Length}");

static byte[] Deflate(byte[] data)
{
    using var ms = new MemoryStream();
    using (var ds = new DeflateStream(ms, CompressionLevel.Optimal, leaveOpen: true)) ds.Write(data, 0, data.Length);
    return ms.ToArray();
}
static byte[] Inflate(byte[] data, int maxLen)
{
    using var ms = new MemoryStream(data);
    using var ds = new DeflateStream(ms, CompressionMode.Decompress);
    var buf = new byte[maxLen]; int total = 0, r;
    while (total < maxLen && (r = ds.Read(buf, total, maxLen - total)) > 0) total += r;
    Array.Resize(ref buf, total); return buf;
}

// confirm decompress at knownOff == bak
var region = new byte[bundle.Length - (int)knownOff];
Array.Copy(bundle, knownOff, region, 0, region.Length);
var dec = Inflate(region, bak.Length + 16);
Console.WriteLine($"inflate@0xD36BA4 len={dec.Length} equalToBak={dec.AsSpan().SequenceEqual(bak)}");

// compress bak -> compare with stored stream to find stored compressed length
byte[] compBak = Deflate(bak);
Console.WriteLine($"myDeflate(bak) len={compBak.Length}  storedStart==myFirst16? " + bundle.AsSpan((int)knownOff, 16).SequenceEqual(compBak.AsSpan(0,16)));
bool exact = (knownOff + compBak.Length <= bundle.Length) && bundle.AsSpan((int)knownOff, compBak.Length).SequenceEqual(compBak);
Console.WriteLine($"stored stream == myDeflate(bak) exactly? {exact}");

// Determine compressed length actually used: find minimal L where inflate(region[0..L]) == bak
int compLen = exact ? compBak.Length : -1;
if (compLen < 0)
{
    int lo = Math.Max(16, compBak.Length - 2048), hi = Math.Min(region.Length, compBak.Length + 2048);
    for (int L = lo; L <= hi; L++)
    {
        var outd = Inflate(region.AsSpan(0, L).ToArray(), bak.Length + 8);
        if (outd.Length == bak.Length && outd.AsSpan().SequenceEqual(bak)) { compLen = L; break; }
    }
}
Console.WriteLine($"detected stored compressed length = {compLen}");

byte[] DeflateLvl(byte[] data, CompressionLevel lvl)
{
    using var ms = new MemoryStream();
    using (var ds = new DeflateStream(ms, lvl, leaveOpen: true)) ds.Write(data, 0, data.Length);
    return ms.ToArray();
}
byte[] compPatchOpt = DeflateLvl(patched, CompressionLevel.Optimal);
byte[] compPatchSmall = DeflateLvl(patched, CompressionLevel.SmallestSize);
byte[] compBakSmall = DeflateLvl(bak, CompressionLevel.SmallestSize);
Console.WriteLine($"patched Optimal={compPatchOpt.Length} Smallest={compPatchSmall.Length} | bak Smallest={compBakSmall.Length}");
byte[] compPatch = compPatchOpt.Length <= compPatchSmall.Length ? compPatchOpt : compPatchSmall;
Console.WriteLine($"chon compressed(patched) len={compPatch.Length}");

int useLen = compLen > 0 ? compLen : compBak.Length;
if (compPatch.Length > useLen)
{
    Console.WriteLine($"!! patched compressed ({compPatch.Length}) LON hon stored ({useLen}) -> khong the ghi de cung kich thuoc");
    return;
}
// build new bundle: overwrite [off .. off+useLen] with compPatch padded zeros
var newBundle = (byte[])bundle.Clone();
Array.Clear(newBundle, (int)knownOff, useLen);
Array.Copy(compPatch, 0, newBundle, (int)knownOff, compPatch.Length);

// verify produced region inflates to patched (padded to bak size)
var vdec = Inflate(newBundle.AsSpan((int)knownOff, useLen).ToArray(), bak.Length);
Console.WriteLine($"verify: new region inflate len={vdec.Length} prefixEqualsPatched={vdec.Length>=patched.Length && vdec.AsSpan(0,patched.Length).SequenceEqual(patched)}");

// load patched from padded temp and read R/kU
var padded = new byte[bak.Length];
Array.Copy(patched, padded, patched.Length);
string tmp = Path.Combine(Path.GetTempPath(), "ns9m_final.dll");
File.WriteAllBytes(tmp, padded);
try {
    var asm = Assembly.LoadFrom(tmp);
    string Call0(string n){ var mi=asm.GetTypes().SelectMany(t=>t.GetMethods(BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic)).FirstOrDefault(m=>m.Name==n&&m.GetParameters().Length==0); return mi?.Invoke(null,null) as string ?? "(null)"; }
    Console.WriteLine("R()  = " + Call0("R"));
    var ku=Call0("kU"); Console.WriteLine("kU() = " + (ku.Length>20?ku[..20]+"...":ku) + $" (len {ku.Length})");
} catch(Exception e){ Console.WriteLine("[reflect] "+e.Message); }

File.WriteAllBytes(outPath, newBundle);
Console.WriteLine("WROTE " + outPath + "  size=" + newBundle.Length);
