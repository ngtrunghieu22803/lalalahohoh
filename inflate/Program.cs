using System;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Reflection;

// Usage: inflate <file> <offsetHex> <maxLen> <outDll>
string file = args[0];
long off = Convert.ToInt64(args[1], 16);
int maxLen = int.Parse(args[2]);
string outp = args[3];

using var fs = new FileStream(file, FileMode.Open, FileAccess.Read);
fs.Seek(off, SeekOrigin.Begin);
var buf = new byte[maxLen];
int total = 0;
try
{
    using var ds = new DeflateStream(fs, CompressionMode.Decompress, leaveOpen: true);
    int r;
    while (total < maxLen && (r = ds.Read(buf, total, maxLen - total)) > 0) total += r;
}
catch (Exception e) { Console.WriteLine("[inflate] stopped: " + e.Message); }
Console.WriteLine($"decompressed {total} bytes");
Array.Resize(ref buf, total);
File.WriteAllBytes(outp, buf);

try
{
    if (args.Length > 4)
    {
        string baseDir = args[4];
        AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
        {
            var name = new AssemblyName(e.Name).Name + ".dll";
            var path = Path.Combine(baseDir, name);
            return File.Exists(path) ? Assembly.LoadFrom(path) : null;
        };
    }
    var asm = Assembly.LoadFrom(outp);
    string Call0(string name)
    {
        var mi = asm.GetTypes().SelectMany(t => t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
            .FirstOrDefault(m => m.Name == name && m.GetParameters().Length == 0);
        return mi?.Invoke(null, null) as string ?? "(null)";
    }
    Console.WriteLine("R()  = " + Call0("R"));
    var ku = Call0("kU");
    Console.WriteLine("kU() = " + (ku.Length > 24 ? ku[..24] + "..." : ku) + $" (len {ku.Length})");
}
catch (Exception e) { Console.WriteLine("[reflect] " + e.Message); }
