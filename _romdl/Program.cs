using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

class Program
{
    const string Server = "https://logachanger.accshopee.com";
    const string PubB64 = "BFRpTpFx7V4AW5n+Erqau6mF51TfAiJMEzU20IA4lUSKUFOi2Jlb5qOiSZf5W7RNjsL37NYtQwgq6+VPQZqNtx8=";
    static readonly string OutDir = @"G:\LogaToolChangerV2\roms";
    static readonly HttpClient Http = new HttpClient { Timeout = TimeSpan.FromHours(2) };

    static async Task<int> Main()
    {
        Directory.CreateDirectory(OutDir);
        var sess = JsonDocument.Parse(await File.ReadAllTextAsync(@"G:\LogaToolChangerV2\session.dat"));
        string session = sess.RootElement.GetProperty("session").GetString()!;
        string key = sess.RootElement.GetProperty("key").GetString()!;
        string hwid = sess.RootElement.GetProperty("hwid").GetString()!;
        long exp = sess.RootElement.GetProperty("exp").GetInt64();
        Console.WriteLine($"key={key} hwid={hwid} exp={exp} now={DateTimeOffset.UtcNow.ToUnixTimeSeconds()}");

        if (DateTimeOffset.UtcNow.ToUnixTimeSeconds() > exp)
        {
            Console.WriteLine("session expired → re-activate...");
            var act = await ApiAsync<ActivateResp>("/license/activate", new { key, hwid });
            if (act == null || !act.ok) { Console.WriteLine("activate fail: " + act?.reason); return 1; }
            session = act.session!;
            exp = act.exp;
            await File.WriteAllTextAsync(@"G:\LogaToolChangerV2\session.dat",
                JsonSerializer.Serialize(new { session, exp, key, hwid }, new JsonSerializerOptions { WriteIndented = true }));
            Console.WriteLine("new exp=" + exp);
        }

        var quota = await ApiAsync<QuotaResp>("/license/quota", new { session, hwid });
        Console.WriteLine("quota: " + JsonSerializer.Serialize(quota));

        var cat = await ApiAsync<JsonElement>("/catalog", new { session, hwid });
        await File.WriteAllTextAsync(Path.Combine(OutDir, "catalog.json"), cat.ToString());
        Console.WriteLine("catalog saved");

        var models = new List<Model>();
        if (cat.ValueKind == JsonValueKind.Object && cat.TryGetProperty("models", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var el in arr.EnumerateArray())
            {
                models.Add(new Model {
                    brand = el.TryGetProperty("brand", out var b) ? b.GetString() ?? "" : "",
                    model = el.TryGetProperty("model", out var m) ? m.GetString() ?? "" : "",
                    hostSoc = el.TryGetProperty("hostSoc", out var h) && h.GetBoolean(),
                    androidVer = el.TryGetProperty("androidVer", out var a) ? a.GetInt32() : 0,
                    // optional device/codename fields if present
                    device = el.TryGetProperty("device", out var d) ? d.GetString() ?? "" :
                             (el.TryGetProperty("codename", out var c) ? c.GetString() ?? "" : "")
                });
            }
        }
        Console.WriteLine($"models={models.Count} hostSoc={models.Count(m => m.hostSoc)}");
        foreach (var m in models.Where(x => x.hostSoc).Take(40))
            Console.WriteLine($"  hostSoc {m.brand} model={m.model} device={m.device} a={m.androidVer}");

        // Known installable ROM devices from Loga (S9/S9+ family etc.)
        var known = new (string device, string model)[] {
            ("star2lte", "SM-G965F"),
            ("star2lte", "SM-G9650"),
            ("starlte", "SM-G960F"),
            ("starlte", "SM-G9600"),
            ("crownlte", "SM-N960F"),
            ("beyond1lte", "SM-G970F"),
            ("beyond2lte", "SM-G973F"),
            ("beyond0lte", "SM-G970F"),
            ("d2s", "SM-N975F"),
            ("d1", "SM-N970F"),
        };

        var probes = new List<(string device, string model, string label)>();
        foreach (var k in known) probes.Add((k.device, k.model, k.device));
        foreach (var m in models)
        {
            if (!string.IsNullOrEmpty(m.device))
                probes.Add((m.device, m.model, m.brand + " " + m.model));
            if (m.hostSoc)
            {
                // hostSoc entries often ARE the recovery ROM targets — model field may be codename
                probes.Add((m.model, m.model, "hostSoc-as-device " + m.model));
                probes.Add((m.model.TrimEnd('*',' '), m.model, "hostSoc-trim " + m.model));
            }
        }
        probes = probes.GroupBy(p => p.device.ToLowerInvariant() + "\t" + p.model)
            .Select(g => g.First()).ToList();

        Console.WriteLine($"probing {probes.Count} /rom/info ...");
        var found = new Dictionary<string, (RomInfo info, string device, string model)>(StringComparer.OrdinalIgnoreCase);
        int n = 0;
        foreach (var (device, model, label) in probes)
        {
            n++;
            RomInfo? info = null;
            try { info = await ApiAsync<RomInfo>("/rom/info", new { session, hwid, device, model }); }
            catch (Exception ex) { Console.WriteLine($"  ERR {device}: {ex.Message}"); continue; }
            if (info != null && info.ok && info.available && !string.IsNullOrEmpty(info.romFile))
            {
                if (!found.ContainsKey(info.romFile!))
                {
                    found[info.romFile!] = (info, device, model);
                    Console.WriteLine($"FOUND {label} => {info.name} file={info.romFile} size={info.romSize} rec={info.recFile}");
                    await File.WriteAllTextAsync(Path.Combine(OutDir, Sanitize(info.romFile!) + ".meta.json"),
                        JsonSerializer.Serialize(new { device, model, label, info }, new JsonSerializerOptions { WriteIndented = true }));
                }
            }
            else if (info != null && info.ok && !info.available)
            {
                // silent
            }
            else if (info != null && !info.ok && n <= 5)
            {
                Console.WriteLine($"  no {device}/{model}: {info.reason}");
            }
            if (n % 25 == 0) Console.WriteLine($"  ... {n}/{probes.Count} found={found.Count}");
        }

        Console.WriteLine($"UNIQUE ROMs available: {found.Count}");
        foreach (var kv in found)
            Console.WriteLine($"  {kv.Key} size={kv.Value.info.romSize} name={kv.Value.info.name}");

        foreach (var kv in found)
        {
            var info = kv.Value.info;
            var dest = Path.Combine(OutDir, Sanitize(info.romFile!));
            if (File.Exists(dest) && new FileInfo(dest).Length > 0 && (info.romSize == 0 || new FileInfo(dest).Length == info.romSize))
            {
                Console.WriteLine("SKIP " + dest);
            }
            else
            {
                Console.WriteLine($"DL ROM {info.romFile} -> {dest}");
                await DownloadAsync(info.romFile!, info.dlToken!, dest, info.romSize);
            }
            if (!string.IsNullOrEmpty(info.recFile) && info.recSize > 0)
            {
                var rdest = Path.Combine(OutDir, Sanitize(info.recFile!));
                if (!(File.Exists(rdest) && new FileInfo(rdest).Length == info.recSize))
                {
                    Console.WriteLine($"DL REC {info.recFile}");
                    // may need fresh token - re-query
                    var again = await ApiAsync<RomInfo>("/rom/info", new { session, hwid, device = kv.Value.device, model = kv.Value.model });
                    var tok = again?.dlToken ?? info.dlToken!;
                    await DownloadAsync(info.recFile!, tok, rdest, info.recSize);
                }
            }
        }
        Console.WriteLine("DONE");
        return 0;
    }

    static string Sanitize(string s) => string.Join("_", s.Split(Path.GetInvalidFileNameChars()));

    static async Task DownloadAsync(string file, string token, string dest, long expect)
    {
        var url = $"{Server}/rom/dl?f={Uri.EscapeDataString(file)}&t={Uri.EscapeDataString(token)}";
        using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead);
        if (!resp.IsSuccessStatusCode)
        {
            var err = await resp.Content.ReadAsStringAsync();
            throw new Exception($"DL HTTP {(int)resp.StatusCode}: {err.Substring(0, Math.Min(200, err.Length))}");
        }
        await using var src = await resp.Content.ReadAsStreamAsync();
        var tmp = dest + ".part";
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
                    Console.WriteLine($"  ↓ {got / 1048576} / {(expect > 0 ? expect / 1048576 : '?')} MB");
                    last = got;
                }
            }
            Console.WriteLine($"  OK {got} bytes");
        }
        if (File.Exists(dest)) File.Delete(dest);
        File.Move(tmp, dest);
    }

    static async Task<T?> ApiAsync<T>(string path, object body)
    {
        var json = JsonSerializer.Serialize(body);
        var (blob, shared) = Encrypt(json);
        using var content = new StringContent(blob, Encoding.UTF8, "application/json");
        using var resp = await Http.PostAsync(Server.TrimEnd('/') + path, content);
        var raw = await resp.Content.ReadAsStringAsync();
        if (!resp.IsSuccessStatusCode)
            throw new Exception($"HTTP {(int)resp.StatusCode} {path}: {raw.Substring(0, Math.Min(180, raw.Length))}");
        var plain = Decrypt(shared, raw);
        if (typeof(T) == typeof(JsonElement))
        {
            object el = JsonSerializer.Deserialize<JsonElement>(plain);
            return (T)el;
        }
        return JsonSerializer.Deserialize<T>(plain, new JsonSerializerOptions { PropertyNameCaseInsensitive = true });
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

    class ActivateResp { public bool ok { get; set; } public string? reason { get; set; } public string? session { get; set; } public long exp { get; set; } }
    class QuotaResp { public bool ok { get; set; } public string? reason { get; set; } public string? plan { get; set; } public string? planName { get; set; } public int freeProfiles { get; set; } public int used { get; set; } public long balanceXu { get; set; } public long expEpoch { get; set; } }
    class Model { public string brand { get; set; } = ""; public string model { get; set; } = ""; public string device { get; set; } = ""; public bool hostSoc { get; set; } public int androidVer { get; set; } }
    class RomInfo
    {
        public bool ok { get; set; }
        public string? reason { get; set; }
        public bool available { get; set; }
        public string? name { get; set; }
        public string? romFile { get; set; }
        public long romSize { get; set; }
        public string? recFile { get; set; }
        public long recSize { get; set; }
        public string? dlToken { get; set; }
        public long decSize { get; set; }
    }
}
