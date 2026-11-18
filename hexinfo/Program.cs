using System;
using System.IO;
using System.Text;

string path = args.Length > 0 ? args[0] : @"G:\LogaToolChangerV2\LogaChanger.exe.orig";
byte[] b = File.ReadAllBytes(path);
Console.WriteLine($"size={b.Length} (0x{b.Length:X})");

if (args.Length >= 4 && args[2] == "dump")
{
    long st = Convert.ToInt64(args[3], 16);
    long ln = Convert.ToInt64(args[4], 16);
    for (long i = st; i < st + ln && i < b.Length; i += 16)
    {
        var line = new StringBuilder();
        line.Append($"{i:X8}: ");
        var asc = new StringBuilder();
        for (int j = 0; j < 16 && i + j < b.Length; j++)
        {
            byte bt = b[(int)(i + j)];
            line.Append(bt.ToString("X2")).Append(' ');
            asc.Append(bt >= 32 && bt < 127 ? (char)bt : '.');
        }
        Console.WriteLine(line.ToString() + "  " + asc);
    }
    return;
}

long dllOff = 0xD36BA4;
long compLen = 479789;
long uncompLen = 1173504;

void FindInt64(long val, string label)
{
    var pat = BitConverter.GetBytes(val);
    int hits = 0;
    for (int i = 0; i + 8 <= b.Length && hits < 6; i++)
    {
        bool ok = true;
        for (int j = 0; j < 8; j++) if (b[i + j] != pat[j]) { ok = false; break; }
        if (ok) { Console.WriteLine($"  {label}={val} (0x{val:X}) found at 0x{i:X}"); hits++; i += 7; }
    }
    if (hits == 0) Console.WriteLine($"  {label}={val} NOT found");
}
FindInt64(dllOff, "dllOff");
FindInt64(compLen, "compLen");
FindInt64(uncompLen, "uncompLen");

// dump last 360 bytes
int tail = Math.Min(360, b.Length);
Console.WriteLine($"--- last {tail} bytes ---");
int s0 = b.Length - tail;
for (int i = s0; i < b.Length; i += 16)
{
    var line = new StringBuilder();

    line.Append($"{i:X8}: ");
    var asc = new StringBuilder();
    for (int j = 0; j < 16 && i + j < b.Length; j++)
    {
        byte bt = b[i + j];
        line.Append(bt.ToString("X2")).Append(' ');
        asc.Append(bt >= 32 && bt < 127 ? (char)bt : '.');
    }
    Console.WriteLine(line.ToString() + "  " + asc);
}
