using System;
using System.IO;
using System.Linq;
using System.Reflection;
using dnlib.DotNet;
using dnlib.DotNet.Emit;

// Usage: patcher <dll> <newUrl> <newKU>  (newKU optional; "-" keeps)
string dll = args.Length > 0 ? args[0] : @"G:\LogaToolChangerV2\qua_trinh_giai\NativeS9Manager.dll";
string newUrl = args.Length > 1 ? args[1] : "http://127.0.0.1:8790";
string newKU = args.Length > 2 ? args[2] : "-";
if (newKU == "-") newKU = File.Exists("kU.txt") ? File.ReadAllText("kU.txt").Trim() : "";

Console.WriteLine("[patcher] dll   = " + dll);
Console.WriteLine("[patcher] url   = " + newUrl);
Console.WriteLine("[patcher] kU    = " + (newKU.Length > 20 ? newKU[..20] + "..." : newKU) + $" (len {newKU.Length})");

var mod = ModuleDefMD.Load(dll);

int patchedR = 0, patchedKU = 0;
foreach (var type in mod.GetTypes())
{
    foreach (var m in type.Methods)
    {
        if (!m.IsStatic || m.MethodSig == null || m.MethodSig.Params.Count != 0) continue;
        if (m.MethodSig.RetType.FullName != "System.String") continue;
        string? repl = null;
        if (m.Name == "R") { repl = newUrl; }
        else if (m.Name == "kU") { repl = newKU; }
        if (repl == null) continue;

        var body = new CilBody { MaxStack = 1 };
        body.Instructions.Add(Instruction.Create(OpCodes.Ldstr, repl));
        body.Instructions.Add(Instruction.Create(OpCodes.Ret));
        m.Body = body;
        if (m.Name == "R") patchedR++; else patchedKU++;
        Console.WriteLine($"[patched] {type.FullName}::{m.Name} -> {(m.Name=="R"?newUrl:(repl[..Math.Min(20,repl.Length)]+"..."))}");
    }
}

Console.WriteLine($"[patcher] R={patchedR}  kU={patchedKU}");
if (patchedR == 0) Console.WriteLine("!! KHONG tim thay R()");
if (patchedKU == 0) Console.WriteLine("!! KHONG tim thay kU()");

string bak = dll + ".bak";
if (!File.Exists(bak)) File.Copy(dll, bak, false);
string tmp = dll + ".patched";
mod.Write(tmp);
mod.Dispose();
File.Move(tmp, dll, true);
Console.WriteLine("[patcher] DONE -> " + dll + " (bak: " + bak + ")");

// verify
try
{
    var asm = Assembly.LoadFrom(dll);
    var tR = asm.GetTypes().FirstOrDefault(t => t.GetMethods(BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic).Any(x => x.Name=="R" && x.GetParameters().Length==0));
    var tK = asm.GetTypes().FirstOrDefault(t => t.GetMethods(BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic).Any(x => x.Name=="kU" && x.GetParameters().Length==0));
    var rv = tR?.GetMethods(BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic).First(x=>x.Name=="R"&&x.GetParameters().Length==0).Invoke(null,null) as string;
    var kv = tK?.GetMethods(BindingFlags.Static|BindingFlags.Public|BindingFlags.NonPublic).First(x=>x.Name=="kU"&&x.GetParameters().Length==0).Invoke(null,null) as string;
    Console.WriteLine("[verify] R()  = " + rv);
    Console.WriteLine("[verify] kU() = " + kv);
}
catch (Exception e) { Console.WriteLine("[verify] skip: " + e.Message); }
