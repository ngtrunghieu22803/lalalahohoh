using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

const string Server = "https://logachanger.accshopee.com";
const string PubB64 = "BFRpTpFx7V4AW5n+Erqau6mF51TfAiJMEzU20IA4lUSKUFOi2Jlb5qOiSZf5W7RNjsL37NYtQwgq6+VPQZqNtx8=";
var outDir = @"G:\LogaToolChangerV2\roms";
using var http = new HttpClient { Timeout = TimeSpan.FromHours(2) };

var sess = JsonDocument.Parse(await File.ReadAllTextAsync(@"G:\LogaToolChangerV2\session.dat"));
string session = sess.RootElement.GetProperty("session").GetString()!;
string key = sess.RootElement.GetProperty("key").GetString()!;
string hwid = sess.RootElement.GetProperty("hwid").GetString()!;
long exp = sess.RootElement.GetProperty("exp").GetInt64();
if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp)
{
    Console.WriteLine("re-activate...");
    var act = await ApiAsync(http, "/license/activate", new { key, hwid });
    using var ad = JsonDocument.Parse(act);
    if (!ad.RootElement.GetProperty("ok").GetBoolean()) { Console.WriteLine(act); return 1; }
    session = ad.RootElement.GetProperty("session").GetString()!;
    exp = ad.RootElement.GetProperty("exp").GetInt64();
    await File.WriteAllTextAsync(@"G:\LogaToolChangerV2\session.dat",
        JsonSerializer.Serialize(new { session, exp, key, hwid }, new JsonSerializerOptions { WriteIndented = true }));
}

Console.WriteLine("query /rom/info crownlte...");
var infoJson = await ApiAsync(http, "/rom/info", new { session, hwid, device = "crownlte", model = "SM-N960F" });
Console.WriteLine(infoJson);
using var info = JsonDocument.Parse(infoJson);
var root = info.RootElement;
if (!root.GetProperty("ok").GetBoolean() || !root.GetProperty("available").GetBoolean())
{
    Console.WriteLine("Note9 not available");
    return 2;
}
string romFile = root.GetProperty("romFile").GetString()!;
long romSize = root.GetProperty("romSize").GetInt64();
string recFile = root.GetProperty("recFile").GetString()!;
long recSize = root.GetProperty("recSize").GetInt64();
string token = root.GetProperty("dlToken").GetString()!;

var romPath = Path.Combine(outDir, romFile);
var recPath = Path.Combine(outDir, recFile);
foreach (var junk in Directory.GetFiles(outDir, romFile + ".part*")) File.Delete(junk);

Console.WriteLine($"DL {romFile} ({romSize} bytes)");
await DownloadAsync(http, romFile, token, romPath, romSize);
await File.WriteAllTextAsync(romPath + ".meta.json",
    JsonSerializer.Serialize(new { device = "crownlte", model = "SM-N960F", label = "crownlte", info = JsonSerializer.Deserialize<JsonElement>(infoJson) },
        new JsonSerializerOptions { WriteIndented = true }));

if (!string.IsNullOrEmpty(recFile) && recSize > 0)
{
    // refresh token
    var again = await ApiAsync(http, "/rom/info", new { session, hwid, device = "crownlte", model = "SM-N960F" });
    using var a2 = JsonDocument.Parse(again);
    token = a2.RootElement.GetProperty("dlToken").GetString()!;
    Console.WriteLine($"DL {recFile} ({recSize} bytes)");
    await DownloadAsync(http, recFile, token, recPath, recSize);
}

Console.WriteLine("=== SUMMARY ===");
foreach (var f in new DirectoryInfo(outDir).GetFiles().OrderBy(f => f.Name))
    Console.WriteLine($"{f.Name}\t{f.Length}");
Console.WriteLine("DONE");
return 0;

static async Task DownloadAsync(HttpClient http, string file, string token, string dest, long expect)
{
    if (File.Exists(dest) && new FileInfo(dest).Length == expect)
    {
        Console.WriteLine("SKIP exists " + dest);
        return;
    }
    var url = $"{Server}/rom/dl?f={Uri.EscapeDataString(file)}&t={Uri.EscapeDataString(token)}";
    using var resp = await http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
    if (!resp.IsSuccessStatusCode)
        throw new Exception($"HTTP {(int)resp.StatusCode}: {await resp.Content.ReadAsStringAsync()}");
    var tmp = dest + ".part";
    await using (var src = await resp.Content.ReadAsStreamAsync())
    await using (var dst = File.Create(tmp))
    {
        var buf = new byte[1024 * 1024];
        long got = 0, last = 0;
        int r;
        while ((r = await src.ReadAsync(buf)) > 0)
        {
            await dst.WriteAsync(buf.AsMemory(0, r));
            got += r;
            if (got - last >= 80L * 1024 * 1024)
            {
                Console.WriteLine($"  ↓ {got / 1048576} / {expect / 1048576} MB");
                last = got;
            }
        }
        Console.WriteLine($"  OK {got} bytes");
        if (expect > 0 && got != expect)
            throw new Exception($"size mismatch got={got} expect={expect}");
    }
    if (File.Exists(dest)) File.Delete(dest);
    File.Move(tmp, dest);
}

static async Task<string> ApiAsync(HttpClient http, string path, object body)
{
    var json = JsonSerializer.Serialize(body);
    var (blob, shared) = Encrypt(json);
    using var content = new StringContent(blob, Encoding.UTF8, "application/json");
    using var resp = await http.PostAsync(Server.TrimEnd('/') + path, content);
    var raw = await resp.Content.ReadAsStringAsync();
    if (!resp.IsSuccessStatusCode)
        throw new Exception($"HTTP {(int)resp.StatusCode} {path}: {raw}");
    return Decrypt(shared, raw);
}

static (string blob, byte[] shared) Encrypt(string plaintext)
{
    using var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    var ephParams = eph.PublicKey.ExportParameters();
    byte[] ephRaw = new byte[65];
    ephRaw[0] = 4;
    Buffer.BlockCopy(ephParams.Q.X!, 0, ephRaw, 1, 32);
    Buffer.BlockCopy(ephParams.Q.Y!, 0, ephRaw, 33, 32);
    var pub = Convert.FromBase64String(PubB64);
    byte[] x = new byte[32], y = new byte[32];
    Buffer.BlockCopy(pub, 1, x, 0, 32);
    Buffer.BlockCopy(pub, 33, y, 0, 32);
    using var server = ECDiffieHellman.Create(new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } });
    byte[] shared = eph.DeriveKeyFromHash(server.PublicKey, HashAlgorithmName.SHA256);
    byte[] pt = Encoding.UTF8.GetBytes(plaintext);
    byte[] nonce = RandomNumberGenerator.GetBytes(12);
    byte[] ct = new byte[pt.Length];
    byte[] tag = new byte[16];
    using (var gcm = new AesGcm(shared, 16)) gcm.Encrypt(nonce, pt, ct, tag);
    byte[] blob = new byte[77 + ct.Length + 16];
    Buffer.BlockCopy(ephRaw, 0, blob, 0, 65);
    Buffer.BlockCopy(nonce, 0, blob, 65, 12);
    Buffer.BlockCopy(ct, 0, blob, 77, ct.Length);
    Buffer.BlockCopy(tag, 0, blob, 77 + ct.Length, 16);
    return (Convert.ToBase64String(blob), shared);
}

static string Decrypt(byte[] shared, string b64)
{
    b64 = b64.Trim().Trim('"');
    byte[] all = Convert.FromBase64String(b64);
    byte[] nonce = new byte[12];
    Buffer.BlockCopy(all, 0, nonce, 0, 12);
    int ctLen = all.Length - 28;
    byte[] ct = new byte[ctLen];
    Buffer.BlockCopy(all, 12, ct, 0, ctLen);
    byte[] tag = new byte[16];
    Buffer.BlockCopy(all, 12 + ctLen, tag, 0, 16);
    byte[] pt = new byte[ctLen];
    using (var gcm = new AesGcm(shared, 16)) gcm.Decrypt(nonce, ct, tag, pt);
    return Encoding.UTF8.GetString(pt);
}
