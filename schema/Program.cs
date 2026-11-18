using System;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Collections.Generic;

string dllPath = @"G:\LogaToolChangerV2\qua_trinh_giai\NativeS9Manager.dll";
string baseDir = @"G:\LogaToolChangerV2\qua_trinh_giai";
AppDomain.CurrentDomain.AssemblyResolve += (s, e) =>
{
    var pth = Path.Combine(baseDir, new AssemblyName(e.Name).Name + ".dll");
    return File.Exists(pth) ? Assembly.LoadFrom(pth) : null;
};
var asm = Assembly.LoadFrom(dllPath);

var seen = new HashSet<string>();
var lines = new List<string>();
foreach (var t in asm.GetTypes())
    foreach (var m in t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic))
    {
        if (m.ReturnType != typeof(string) || m.GetParameters().Length != 0) continue;
        string val;
        try { val = (string)m.Invoke(null, null); } catch { continue; }
        if (string.IsNullOrEmpty(val) || !seen.Add(val)) continue;
        lines.Add(m.Name + "\t" + val.Replace("\r", "\\r").Replace("\n", "\\n").Replace("\t", "\\t"));
    }
File.WriteAllLines(@"G:\LogaToolChangerV2\schema\all_strings.txt", lines);
Console.WriteLine("dumped " + lines.Count + " strings -> all_strings.txt");
