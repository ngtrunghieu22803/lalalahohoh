using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO.Compression;

string baseDir = @"G:\LogaToolChangerV2\local_server";
byte[] localSeed = Convert.FromBase64String(File.ReadAllText(Path.Combine(baseDir, "local_seed.b64")).Trim());
byte[] sPub = Convert.FromBase64String(File.ReadAllText(Path.Combine(baseDir, "kU.txt")).Trim());
var sPubEc = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = sPub[1..33], Y = sPub[33..65] } };
using var t = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
using var sPubEcdh = ECDiffieHellman.Create(sPubEc);
byte[] tKey = t.DeriveKeyFromHash(sPubEcdh.PublicKey, HashAlgorithmName.SHA256);
byte[] tPub = Uncompressed(t.ExportParameters(false));
using var http = new HttpClient();

(byte[] backup, string serial, string model) Fetch(string forcedModel)
{
    string payload = JsonSerializer.Serialize(new { brand = "samsung", model = forcedModel, androidVer = 13, modelRandom = false });
    byte[] tn = RandomNumberGenerator.GetBytes(12), tc = new byte[Encoding.UTF8.GetByteCount(payload)], tt = new byte[16];
    using (var g = new AesGcm(tKey, 16)) g.Encrypt(tn, Encoding.UTF8.GetBytes(payload), tc, tt);
    var req = new byte[65 + 12 + tc.Length + 16];
    Buffer.BlockCopy(tPub,0,req,0,65); Buffer.BlockCopy(tn,0,req,65,12); Buffer.BlockCopy(tc,0,req,77,tc.Length); Buffer.BlockCopy(tt,0,req,77+tc.Length,16);
    string b64 = new StreamReader(http.PostAsync("http://127.0.0.1:8790/identity/new", new StringContent(Convert.ToBase64String(req))).Result.Content.ReadAsStream()).ReadToEnd();
    byte[] rb = Convert.FromBase64String(b64);
    var rn = rb[0..12]; int cl = rb.Length-28; var rc = rb[12..(12+cl)]; var rt = rb[(12+cl)..];
    var pt = new byte[cl];
    using (var g = new AesGcm(tKey, 16)) g.Decrypt(rn, rc, rt, pt);
    using var d = JsonDocument.Parse(Encoding.UTF8.GetString(pt));
    return (Convert.FromBase64String(d.RootElement.GetProperty("backupB64").GetString()!), d.RootElement.GetProperty("serial").GetString() ?? "", d.RootElement.GetProperty("model").GetString() ?? "");
}

string[] Lines(byte[] backup)
{
    byte[] salt = backup[4..20];
    byte[] key = SHA256.HashData(Cat(localSeed, salt));
    byte[] iv = SHA256.HashData(Cat(salt, localSeed))[..16];
    using var aes = Aes.Create(); aes.Key = key; aes.IV = iv; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None;
    byte[] zip = aes.CreateDecryptor().TransformFinalBlock(backup, 20, backup.Length-20);
    using var z = new ZipArchive(new MemoryStream(zip), ZipArchiveMode.Read);
    var e = z.GetEntry("system_root/system/build.prop")!;
    using var sr = new StreamReader(e.Open());
    return sr.ReadToEnd().Replace("\r","").Split('\n');
}

var want = new[]{"ro.product.model=","ro.product.system.model=","ro.product.system.device=","ro.product.vendor.model=","ro.product.vendor.device=","ro.build.version.incremental=","ro.build.display.id=","ro.build.description=","ro.build.flavor=","ro.build.product=","ro.system.build.fingerprint=","ro.boot.serialno2=","ro.board.platform=","ro.hardware="};
foreach (var forced in new[] { "SM-S918B", "Pixel 7", "SM-G960F" })
{
    var (bk, ser, mdl) = Fetch(forced);
    var lines = Lines(bk);
    Console.WriteLine($"=== forced model={forced}  -> resp(model={mdl}, serial={ser}) ===");
    foreach (var line in lines)
        foreach (var w in want)
            if (line.StartsWith(w)) { Console.WriteLine("   " + line); break; }
    // cảnh báo nếu lẫn chip khác
    bool hwOk = lines.Any(l => l.Contains("star2lte")) && lines.Any(l => l.Contains("exynos9810"));
    bool badSoc = lines.Any(l => l.Contains("kalama") || l.Contains("SM8550") || l.Contains("dm1q") || l.Contains("dm3q"));
    Console.WriteLine($"   HARDWARE_PRESERVED_S9={hwOk}  foreignSocMixed={badSoc}");
}
Console.WriteLine("Done.");

static byte[] Cat(byte[] a, byte[] b){var r=new byte[a.Length+b.Length];Buffer.BlockCopy(a,0,r,0,a.Length);Buffer.BlockCopy(b,0,r,a.Length,b.Length);return r;}
static byte[] Uncompressed(ECParameters p){var a=new byte[65];a[0]=4;Buffer.BlockCopy(p.Q.X!,0,a,1,32);Buffer.BlockCopy(p.Q.Y!,0,a,33,32);return a;}
