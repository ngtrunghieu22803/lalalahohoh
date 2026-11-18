using System;
using System.IO;
using System.Linq;
using System.Reflection;

// Replace the embedded NativeS9Manager.dll inside the single-file bundle, same length.
// Usage: bundler <bundleOrig.exe> <origDll(.bak)> <patchedDll> <outExe>
string bundlePath = args[0];
string origDllPath = args[1];
string patchedDllPath = args[2];
string outPath = args[3];

byte[] bundle = File.ReadAllBytes(bundlePath);
byte[] origDll = File.ReadAllBytes(origDllPath);
byte[] patched = File.ReadAllBytes(patchedDllPath);
Console.WriteLine($"bundle={bundle.Length} origDll={origDll.Length} patched={patched.Length}");

if (patched.Length > origDll.Length)
{
    Console.WriteLine("!! patched dll LON hon orig -> khong the giu nguyen kich thuoc"); return;
}
// pad patched to orig length with zeros
var padded = new byte[origDll.Length];
Array.Copy(patched, padded, patched.Length);

// find embedded region = origDll bytes in bundle
ReadOnlySpan<byte> hs = bundle.AsSpan();
ReadOnlySpan<byte> needle = origDll.AsSpan();
int off = -1, from = 0;
while (true)
{
    int idx = hs[from..].IndexOf(needle[..64]);
    if (idx < 0) break;
    idx += from;
    if (idx + origDll.Length <= bundle.Length && hs.Slice(idx, origDll.Length).SequenceEqual(needle))
    { off = idx; break; }
    from = idx + 1;
}
if (off < 0) { Console.WriteLine("!! KHONG tim thay vung DLL nhung goc (raw)."); return; }
Console.WriteLine($"tim thay embedded dll tai offset 0x{off:X} (0x{off:X}..0x{off+origDll.Length:X})");

// replace
Array.Copy(padded, 0, bundle, off, origDll.Length);
File.WriteAllBytes(outPath, bundle);
Console.WriteLine("DONE -> " + outPath);

// verify: extract region, load, call R()/kU()
string tmp = Path.Combine(Path.GetTempPath(), "ns9m_check.dll");
File.WriteAllBytes(tmp, padded);
try
{
    var asm = Assembly.LoadFrom(tmp);
    string Call0(string name)
    {
        var t = asm.GetTypes().FirstOrDefault(x => x.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic).Any(m => m.Name == name && m.GetParameters().Length == 0));
        var mi = t?.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic).First(m => m.Name == name && m.GetParameters().Length == 0);
        return mi?.Invoke(null, null) as string ?? "(null)";
    }
    Console.WriteLine("[verify] R()  = " + Call0("R"));
    var ku = Call0("kU");
    Console.WriteLine("[verify] kU() = " + (ku.Length > 20 ? ku[..20] + "..." : ku) + $" (len {ku.Length})");
}
catch (Exception e) { Console.WriteLine("[verify] skip: " + e.Message); }
