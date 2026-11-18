using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.IO.Compression;

// ===================== CONFIG =====================
int PORT = args.Length > 0 ? int.Parse(args[0]) : 8790;
string TPLDIR = Path.Combine(AppContext.BaseDirectory, "templates");
if (!Directory.Exists(TPLDIR)) TPLDIR = @"G:\LogaToolChangerV2\local_server\templates";
string CATALOG = Path.Combine(AppContext.BaseDirectory, "catalog.json");
if (!File.Exists(CATALOG)) CATALOG = @"G:\LogaToolChangerV2\roms\catalog.json";

// ===================== SERVER KEY (ECDH P-256) =====================
string KEYBIN = "serverkey.bin";
ECDiffieHellman serverEcdh = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
if (File.Exists(KEYBIN))
{
    serverEcdh.ImportPkcs8PrivateKey(File.ReadAllBytes(KEYBIN), out _);
}
else
{
    File.WriteAllBytes(KEYBIN, serverEcdh.ExportPkcs8PrivateKey());
}
byte[] serverPub = ToUncompressed(serverEcdh.ExportParameters(false));
string kU = Convert.ToBase64String(serverPub);
File.WriteAllText("kU.txt", kU);
Console.WriteLine("=== kU (gán vào client kU()) ===");
Console.WriteLine(kU);
Console.WriteLine("[templates] " + TPLDIR + " exists=" + Directory.Exists(TPLDIR));

// ===================== SEED CỐ ĐỊNH (dùng chung cho /activate và seal backup) =====================
string SEEDFILE = "local_seed.b64";
byte[] localSeed;
if (File.Exists(SEEDFILE))
{
    localSeed = Convert.FromBase64String(File.ReadAllText(SEEDFILE).Trim());
    if (localSeed.Length != 32) localSeed = RandomNumberGenerator.GetBytes(32);
}
else localSeed = RandomNumberGenerator.GetBytes(32);
File.WriteAllText(SEEDFILE, Convert.ToBase64String(localSeed));
Console.WriteLine("[seed] local_seed 32b = " + Convert.ToBase64String(localSeed));

// ===== ChaCha20 (IETF: key 32B, nonce 12B, counter 32-bit) =====
static byte[] ChaCha20Xor(byte[] key, byte[] nonce, uint counter, byte[] data)
{
    if (key.Length != 32) throw new ArgumentException("key must be 32 bytes");
    if (nonce.Length != 12) throw new ArgumentException("nonce must be 12 bytes");
    uint[] s = new uint[16];
    s[0] = 0x61707865; s[1] = 0x3320646e; s[2] = 0x79622d32; s[3] = 0x6b206574;
    for (int i = 0; i < 8; i++) s[4 + i] = BitConverter.ToUInt32(key, i * 4);
    s[12] = counter;
    s[13] = BitConverter.ToUInt32(nonce, 0);
    s[14] = BitConverter.ToUInt32(nonce, 4);
    s[15] = BitConverter.ToUInt32(nonce, 8);
    static uint Rotl(uint x, int n) => (x << n) | (x >> (32 - n));
    static void Qr(uint[] x, int a, int b, int c, int d)
    {
        x[a] += x[b]; x[d] ^= x[a]; x[d] = Rotl(x[d], 16);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = Rotl(x[b], 12);
        x[a] += x[b]; x[d] ^= x[a]; x[d] = Rotl(x[d], 8);
        x[c] += x[d]; x[b] ^= x[c]; x[b] = Rotl(x[b], 7);
    }
    var outb = new byte[data.Length];
    uint[] x = new uint[16];
    byte[] ks = new byte[64];
    int off = 0;
    while (off < data.Length)
    {
        Array.Copy(s, x, 16);
        for (int r = 0; r < 10; r++)
        {
            Qr(x, 0, 4, 8, 12); Qr(x, 1, 5, 9, 13); Qr(x, 2, 6, 10, 14); Qr(x, 3, 7, 11, 15);
            Qr(x, 0, 5, 10, 15); Qr(x, 1, 6, 11, 12); Qr(x, 2, 7, 8, 13); Qr(x, 3, 4, 9, 14);
        }
        for (int i = 0; i < 16; i++) BitConverter.TryWriteBytes(ks.AsSpan(i * 4), x[i] + s[i]);
        int n = Math.Min(64, data.Length - off);
        for (int i = 0; i < n; i++) outb[off + i] = (byte)(data[off + i] ^ ks[i]);
        off += n;
        s[12] = unchecked(s[12] + 1);
    }
    return outb;
}

// ===== Seal/Unseal `.backup` kiểu logaapply =====
static byte[] Cat(byte[] a, byte[] b)
{
    var r = new byte[a.Length + b.Length];
    Buffer.BlockCopy(a, 0, r, 0, a.Length);
    Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
    return r;
}
static byte[] AesCbc(bool enc, byte[] key, byte[] iv, byte[] data)
{
    using var aes = Aes.Create();
    aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.None;
    aes.Key = key; aes.IV = iv;
    using var t = enc ? aes.CreateEncryptor() : aes.CreateDecryptor();
    return t.TransformFinalBlock(data, 0, data.Length);
}
// Công thức đã verify bằng oracle (chạy logaapply thật): salt=header[4:20];
// A=SHA256(seed|salt)=AES-256 key; IV=SHA256(salt|seed)[:16]; AES-CBC; plaintext bội số 16.
byte[] SealBackup(byte[] paddedPlain)
{
    if (paddedPlain.Length % 16 != 0) throw new Exception("plaintext khong boi so 16");
    byte[] salt = RandomNumberGenerator.GetBytes(16);
    byte[] A = SHA256.HashData(Cat(localSeed, salt));
    byte[] iv = SHA256.HashData(Cat(salt, localSeed))[..16];
    byte[] ct = AesCbc(true, A, iv, paddedPlain);
    byte[] outb = new byte[20 + ct.Length];
    outb[0] = (byte)'L'; outb[1] = (byte)'G'; outb[2] = (byte)'B'; outb[3] = (byte)'1';
    Buffer.BlockCopy(salt, 0, outb, 4, 16);
    Buffer.BlockCopy(ct, 0, outb, 20, ct.Length);
    return outb;
}
byte[] UnsealBackup(byte[] backup)
{
    if (backup.Length < 20 || backup[0] != 'L' || backup[1] != 'G' || backup[2] != 'B' || backup[3] != '1')
        throw new Exception("magic sai");
    byte[] salt = backup[4..20];
    byte[] A = SHA256.HashData(Cat(localSeed, salt));
    byte[] iv = SHA256.HashData(Cat(salt, localSeed))[..16];
    return AesCbc(false, A, iv, backup[20..]);
}


static byte[] ToUncompressed(ECParameters p)
{
    var a = new byte[65]; a[0] = 4;
    Buffer.BlockCopy(p.Q.X!, 0, a, 1, 32);
    Buffer.BlockCopy(p.Q.Y!, 0, a, 33, 32);
    return a;
}
string ExtractBlob(string body)
{
    body = body.Trim();
    if (body.StartsWith("{"))
    {
        using var d = JsonDocument.Parse(body);
        foreach (var n in new[] { "d", "data", "blob", "p" })
            if (d.RootElement.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String) return v.GetString()!;
    }
    return body;
}
byte[] DeriveReqKey(string body)
{
    byte[] raw = Convert.FromBase64String(ExtractBlob(body));
    var x = raw[1..33]; var y = raw[33..65];
    var ce = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = x, Y = y } };
    using var client = ECDiffieHellman.Create(ce);
    return serverEcdh.DeriveKeyFromHash(client.PublicKey, HashAlgorithmName.SHA256);
}
string DecryptReq(string body, out byte[] key)
{
    byte[] raw = Convert.FromBase64String(ExtractBlob(body));
    key = DeriveReqKey(body);
    var nonce = raw[65..77];
    int ctLen = raw.Length - 65 - 12 - 16;
    var ct = raw[77..(77 + ctLen)];
    var tag = raw[(77 + ctLen)..];
    var pt = new byte[ctLen];
    using var gcm = new AesGcm(key, 16);
    gcm.Decrypt(nonce, ct, tag, pt);
    return Encoding.UTF8.GetString(pt);
}
string EncryptResp(byte[] key, string json)
{
    var pt = Encoding.UTF8.GetBytes(json);
    var nonce = RandomNumberGenerator.GetBytes(12);
    var ct = new byte[pt.Length]; var tag = new byte[16];
    using (var gcm = new AesGcm(key, 16)) gcm.Encrypt(nonce, pt, ct, tag);
    var outb = new byte[12 + ct.Length + 16];
    Buffer.BlockCopy(nonce, 0, outb, 0, 12);
    Buffer.BlockCopy(ct, 0, outb, 12, ct.Length);
    Buffer.BlockCopy(tag, 0, outb, 12 + ct.Length, 16);
    return Convert.ToBase64String(outb);
}

// ===================== SERVER LOOP =====================
var listener = new HttpListener();
listener.Prefixes.Add($"http://127.0.0.1:{PORT}/");
listener.Prefixes.Add($"http://localhost:{PORT}/");
listener.Start();
Console.WriteLine($"[server] listening {PORT}");
while (true)
{
    var ctx = listener.GetContext();
    _ = Task.Run(() =>
    {
        try
        {
            string body = new StreamReader(ctx.Request.InputStream, Encoding.UTF8).ReadToEnd();
            string path = ctx.Request.Url!.AbsolutePath;
            string json = DecryptReq(body, out var key);
            Console.WriteLine($"[{path}] req len={json.Length}");
            string resp = path switch
            {
                "/catalog" => DoCatalog(),
                "/identity/new" => DoIdentity(json),
                "/apply/cmds" => DoApplyCmds(json),
                "/activate" => DoActivate(json),
                "/license/activate" => DoLicense(),
                "/brandfw" => JsonSerializer.Serialize(new { ok = true, reason = "ok", cleanup = Array.Empty<string>(), files = Array.Empty<object>() }),
                _ => JsonSerializer.Serialize(new { ok = true, reason = "ok" })
            };
            var bytes = Encoding.UTF8.GetBytes(EncryptResp(key, resp));
            ctx.Response.ContentType = "text/plain";
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.OutputStream.Close();
        }
        catch (Exception ex)
        {
            Console.WriteLine("[ERR] " + ex.Message);
            try { ctx.Response.StatusCode = 500; ctx.Response.Close(); } catch { }
        }
    });
}

// ===================== ENDPOINTS =====================
string DoCatalog()
{
    try { return File.ReadAllText(CATALOG); }
    catch { return JsonSerializer.Serialize(new { ok = false, reason = "no catalog" }); }
}

string DoIdentity(string reqJson)
{
    using var d = JsonDocument.Parse(reqJson);
    string brand = Get(d, "brand") ?? "samsung";
    string model = Get(d, "model") ?? "SM-G965F";
    int androidVer = d.RootElement.TryGetProperty("androidVer", out var av) && av.ValueKind == JsonValueKind.Number ? av.GetInt32() : 13;
    if (string.IsNullOrWhiteSpace(brand)) brand = "samsung";
    if (string.IsNullOrWhiteSpace(model)) model = "SM-G965F";

    bool modelRandom = GetBool(d, "modelRandom") || GetBool(d, "ModelRandom") || GetBool(d, "randomModel");
    bool brandRandom = GetBool(d, "brandRandom") || GetBool(d, "BrandRandom") || GetBool(d, "randomBrand");
    // CHANGE = GIỮ NHẤT QUÁN S9+ (SM-G965F / star2lte / exynos9810). Không trộn model ngoài.
    // Mỗi lần change chỉ đổi serial/IMEI/Meid/MAC/SIM (+/data wipe đổi Android ID) — thứ Shopee dùng gắn thiết bị.
    var hw = Specs.For("samsung", "SM-G965F");
    var id = RandId.Create(hw, androidVer, false, false);
    byte[] zip = BuildIdpack(hw, id);       // zip đã được pad thành bội số 16
    byte[] sealedBackup = SealBackup(zip);
    byte[] back = UnsealBackup(sealedBackup);
    bool rt = back.AsSpan().SequenceEqual(zip);
    string backupId = "L" + DateTimeOffset.UtcNow.ToUnixTimeSeconds() + "-" + Guid.NewGuid().ToString("N")[..8];

    var resp = new Dictionary<string, object?>
    {
        ["ok"] = true,
        ["reason"] = "ok",
        ["backupId"] = backupId,
        ["backupB64"] = Convert.ToBase64String(sealedBackup),
        ["model"] = hw.model,
        ["serial"] = id.SerialNo,        // PHẢI khớp ro.boot.serialno2 trong build.prop (tool verify bước áp cây)
        ["screenW"] = hw.w,
        ["screenH"] = hw.h,
        ["screenDpi"] = hw.dpi,
        ["lat"] = id.Lat,
        ["lon"] = id.Lon,
        ["brightness"] = int.TryParse(id.Brightness, out var br) ? br : 120,
        ["board"] = hw.board,
        ["platform"] = hw.platform,
        ["brand"] = "samsung",
        ["provSig"] = "",            // rỗng => bỏ ghi provSig
        ["androidVer"] = androidVer
    };
    Console.WriteLine($"[identity] {brand} {model} serial={id.SerialNo} -> zip={zip.Length}b sealed={sealedBackup.Length}b magic={(char)sealedBackup[0]}{(char)sealedBackup[1]}{(char)sealedBackup[2]}{(char)sealedBackup[3]} roundtrip={rt}");
    return JsonSerializer.Serialize(resp);
}

string DoApplyCmds(string reqJson)
{
    // Overlay idtree -> SYSTEM + VENDOR. Remount rw ĐÚNG theo block device (giống IA của tool)
    // rồi copy; copy cả /system_root/system và /system; sync.
    var cmds = new List<string>
    {
        "mkdir -p /system_root 2>/dev/null",
        "mount /dev/block/platform/11120000.ufs/by-name/SYSTEM /system_root 2>/dev/null",
        "mount /system_root 2>/dev/null",
        "mount -o rw,remount /dev/block/platform/11120000.ufs/by-name/SYSTEM /system_root 2>/dev/null",
        "mount -o rw,remount /system_root 2>/dev/null",
        "mount /system 2>/dev/null; mount -o rw,remount /system 2>/dev/null; mount -o rw,remount / 2>/dev/null",
        "cp -rf /tmp/idtree/system_root/system/. /system_root/system/ 2>/dev/null",
        "cp -rf /tmp/idtree/system_root/system/. /system/. 2>/dev/null",
        "mount /dev/block/platform/11120000.ufs/by-name/VENDOR /vendor 2>/dev/null || mount /dev/block/platform/11120000.ufs/by-name/vendor /vendor 2>/dev/null",
        "mount -o rw,remount /vendor 2>/dev/null",
        "cp -rf /tmp/idtree/vendor/. /vendor/ 2>/dev/null",
        "sync",
    };
    return JsonSerializer.Serialize(new { ok = true, reason = "ok", applyCmds = cmds.ToArray(), farmCmds = Array.Empty<string>() });
}

string DoLicense() =>
    JsonSerializer.Serialize(new { ok = true, reason = "ok", expire = "2099-12-31", quota = 999999, balance = 999999, status = "active" });

// /activate : provision seed (sealed tới public key máy) + ký q.sig bằng khoá server (client verify = kU)
string DoActivate(string reqJson)
{
    // 1) Tìm public key của máy trong payload (base64 của điểm EC 65 byte, byte đầu = 0x04)
    byte[]? clientPub = null;
    string dump = "";
    using (var d = JsonDocument.Parse(reqJson))
    {
        foreach (var pr in d.RootElement.EnumerateObject())
        {
            if (pr.Value.ValueKind != JsonValueKind.String) continue;
            string s = pr.Value.GetString() ?? "";
            dump += pr.Name + "=" + (s.Length > 24 ? s[..24] + "..." : s) + "  ";
            if (clientPub == null && s.Length >= 80)
            {
                try
                {
                    var b = Convert.FromBase64String(s);
                    if (b.Length == 65 && b[0] == 4) clientPub = b;
                }
                catch { }
            }
        }
    }
    Console.WriteLine("[activate] fields: " + dump);
    if (clientPub == null)
    {
        Console.WriteLine("[activate] KHÔNG tìm thấy devicePub -> trả ok=false");
        return JsonSerializer.Serialize(new { ok = false, reason = "no devicePub" });
    }

    // 2) ECDH: eph (server) <-> clientPub ; key = SHA256(shared)
    using var eph = ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
    var peerParams = new ECParameters { Curve = ECCurve.NamedCurves.nistP256, Q = new ECPoint { X = clientPub[1..33], Y = clientPub[33..65] } };
    using (var peer = ECDiffieHellman.Create(peerParams))
    {
        byte[] key = eph.DeriveKeyFromHash(peer.PublicKey, HashAlgorithmName.SHA256);

        // 3) seed = localSeed CỐ ĐỊNH (khớp với lúc seal backup) + seal AES-GCM tới máy
        byte[] seed = localSeed;
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ct = new byte[seed.Length];
        byte[] tag = new byte[16];
        using (var gcm = new AesGcm(key, 16)) gcm.Encrypt(nonce, seed, ct, tag);

        byte[] ephPubRaw = ToUncompressed(eph.ExportParameters(false));
        string ephPubB64 = Convert.ToBase64String(ephPubRaw);
        string nonceB64 = Convert.ToBase64String(nonce);
        string ctB64 = Convert.ToBase64String(ct);
        string tagB64 = Convert.ToBase64String(tag);

        // 4) message2 y hệt client dựng:  act|ok|reason|ephPub|nonce|ct|tag|token|exp   (ok bool -> "True")
        string token = Guid.NewGuid().ToString("N");
        long exp = DateTimeOffset.UtcNow.AddDays(30).ToUnixTimeSeconds();
        string message2 = "act|" + true + "|" + "ok" + "|" + ephPubB64 + "|" + nonceB64 + "|" + ctB64 + "|" + tagB64 + "|" + token + "|" + exp;

        // 5) ký bằng khoá server (client verify bằng kU()) : ECDSA P-256 / SHA256 / P1363
        var srvParams = serverEcdh.ExportParameters(true);
        string sigB64;
        using (var ecdsa = ECDsa.Create(srvParams))
            sigB64 = Convert.ToBase64String(ecdsa.SignData(Encoding.UTF8.GetBytes(message2), HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation));

        Console.WriteLine($"[activate] seed={seed.Length}b -> sealed, exp={exp}");

        // 6) Q trả về (ok là JSON bool true; các string khớp đúng cái đã ký ở trên)
        var resp = new Dictionary<string, object?>
        {
            ["ok"] = true,
            ["reason"] = "ok",
            ["seed"] = new Dictionary<string, object?>
            {
                ["ephPub"] = ephPubB64,
                ["nonce"] = nonceB64,
                ["ct"] = ctB64,
                ["tag"] = tagB64
            },
            ["token"] = token,
            ["exp"] = exp,
            ["sig"] = sigB64,
            ["provSig"] = ""   // rỗng => bỏ ghi prov_sig (sẽ bật khi biết định dạng logadec cần)
        };
        return JsonSerializer.Serialize(resp);
    }
}

static string? Get(JsonDocument d, string n) =>
    d.RootElement.TryGetProperty(n, out var v) && v.ValueKind == JsonValueKind.String ? v.GetString() : null;

static bool GetBool(JsonDocument d, string n)
{
    if (!d.RootElement.TryGetProperty(n, out var v)) return false;
    return v.ValueKind switch
    {
        JsonValueKind.True => true,
        JsonValueKind.False => false,
        JsonValueKind.Number => v.GetInt32() != 0,
        JsonValueKind.String => v.GetString() is string s && (s == "1" || s.Equals("true", StringComparison.OrdinalIgnoreCase)),
        _ => false
    };
}

// ===================== IDPACK (TEMPLATE-BASED) =====================
byte[] BuildIdpack(Spec s, RandId id)
{
    // 2 pass: pass 1 (pad rỗng) để đo độ dài, pass 2 thêm đúng D byte để tổng là bội số 16.
    byte[] first = BuildIdpackOnce(s, id, 0);
    int D = (16 - (first.Length % 16)) % 16;
    if (D == 0) return first;
    return BuildIdpackOnce(s, id, D);
}
byte[] BuildIdpackOnce(Spec s, RandId id, int padSize)
{
    using var ms = new MemoryStream();
    using (var zip = new ZipArchive(ms, ZipArchiveMode.Create, true))
    {
        foreach (var file in Directory.EnumerateFiles(TPLDIR, "*", SearchOption.AllDirectories))
        {
            string rel = Path.GetRelativePath(TPLDIR, file).Replace('\\', '/');
            byte[] data = File.ReadAllBytes(file);
            if (!IsBinary(data))
            {
                string fn = Path.GetFileName(file);
                string txt = Replace(Encoding.UTF8.GetString(data), s);
                string? ov = id.Get(fn);
                if (ov != null) txt = ov;            // ghi đè danh tính random (Utils/*)
                if (fn.Equals("build.prop", StringComparison.OrdinalIgnoreCase))
                    txt = System.Text.RegularExpressions.Regex.Replace(txt, "(?m)^ro\\.boot\\.serialno2=.*$", "ro.boot.serialno2=" + id.SerialNo);
                data = Encoding.UTF8.GetBytes(txt);
            }
            var e = zip.CreateEntry(rel, CompressionLevel.Optimal);
            using var so = e.Open(); so.Write(data, 0, data.Length);
        }
        // entry đệm để tổng zip = bội số 16; ở root nên KHÔNG bị copy vào system.
        var pe = zip.CreateEntry("__pad", CompressionLevel.NoCompression);
        using var pso = pe.Open();
        if (padSize > 0) { var b = new byte[padSize]; RandomNumberGenerator.Fill(b); pso.Write(b, 0, padSize); }
    }
    return ms.ToArray();
}
static bool IsBinary(byte[] b)
{
    int n = Math.Min(b.Length, 1024);
    for (int i = 0; i < n; i++) if (b[i] == 0) return true;
    return false;
}

// Đổi danh tính S9 (template) -> model/brand/soc đích; giữ nguyên layout để boot an toàn.
// Đổi danh tính -> model (cosmetic) + brand; GIỮ NGUYÊN device/board/soc/platform/fingerprint-device
// của S9 (star2lte/universal9810/exynos9810) để máy vẫn BOOT được.
static string Replace(string s, Spec sp)
{
    string bl = sp.brand.ToLowerInvariant();
    foreach (var m in new[] { "SM-G965F", "SM-G960F", "SM-N960F" }) s = s.Replace(m, sp.model);
    string bare = sp.model.StartsWith("SM-") ? sp.model[3..] : sp.model.Replace(" ", "");
    foreach (var m in new[] { "G965F", "G960F", "N960F" }) s = s.Replace(m, bare);
    s = s.Replace("samsung", bl);
    // Chuẩn hoá nhất quán S9+ (template có vài dòng starlte/flavor của S9 -> S9+ star2lte)
    s = s.Replace("starltexx", "star2ltexx").Replace("starlte", "star2lte");
    return s;
}

// ===================== SPEC =====================
record Spec(string brand, string model, string device, string board, string platform,
            string socMaker, string socModel, int w, int h, int dpi)
{
    public string Lat() => "20.9" + Random.Shared.Next(100000, 999999);
    public string Lon() => "105.8" + Random.Shared.Next(100000, 999999);
}

static class Specs
{
    static readonly Dictionary<string, (string dev, string board, string plat, string sm, string so, int w, int h, int dpi)> M = new(StringComparer.OrdinalIgnoreCase)
    {
        ["SM-G965F"] = ("star2lte", "universal9810", "exynos9810", "Samsung", "exynos9810", 1440, 2960, 560),
        ["SM-G960F"] = ("star2lte", "universal9810", "exynos9810", "Samsung", "exynos9810", 1440, 2960, 570),
        ["SM-N960F"] = ("star2lte", "universal9810", "exynos9810", "Samsung", "exynos9810", 1440, 2960, 515),
        ["SM-S918B"] = ("dm3q", "kalama", "kalama", "Qualcomm", "SM8550", 1440, 3088, 500),
        ["SM-S911B"] = ("dm1q", "kalama", "kalama", "Qualcomm", "SM8550", 1080, 2340, 425),
        ["Pixel 7"] = ("panther", "gs201", "gs201", "Google", "Tensor G2", 1080, 2400, 416),
        ["Pixel 7a"] = ("lynx", "gs201", "gs201", "Google", "Tensor G2", 1080, 2400, 429),
        ["CPH2449"] = ("salami", "kalama", "kalama", "Qualcomm", "SM8550", 1440, 3216, 525),
        ["RMX3771"] = ("RE58E2", "m6833", "m6833", "MediaTek", "MT6833", 1080, 2412, 394),
    };
    public static Spec For(string brand, string model)
    {
        if (M.TryGetValue(model, out var v))
            return new Spec(brand, model, v.dev, v.board, v.plat, v.sm, v.so, v.w, v.h, v.dpi);
        return new Spec(brand, model, model.ToLowerInvariant().Replace(" ", ""), "generic", "generic", "Generic", "SoC", 1080, 2400, 400);
    }
    public static string RandomModel()
    {
        var list = M.Keys.Where(k => !k.Equals("SM-G965F", StringComparison.OrdinalIgnoreCase)
                                  && !k.Equals("SM-G960F", StringComparison.OrdinalIgnoreCase)
                                  && !k.Equals("SM-N960F", StringComparison.OrdinalIgnoreCase)).ToList();
        return list[Random.Shared.Next(list.Count)];
    }
}

// Sinh danh tính random (vùng VN) và map theo tên file Utils.
sealed class RandId
{
    readonly Dictionary<string, string> map = new(StringComparer.Ordinal);
    public string? Get(string name) => map.TryGetValue(name, out var v) ? v : null;
    public string SerialNo => map.TryGetValue("SerialNo", out var v) ? v : "";
    public string Lat => map.TryGetValue("__lat__", out var v) ? v : "20.900000";
    public string Lon => map.TryGetValue("__lon__", out var v) ? v : "105.800000";
    public string Brightness => map.TryGetValue("__brightness__", out var v) ? v : "120";

    public static RandId Create(Spec s, int androidVer, bool modelRandom, bool brandRandom)
    {
        var rng = new Random(BitConverter.ToInt32(RandomNumberGenerator.GetBytes(4)));
        string digits(int n) { var c = new char[n]; for (int i = 0; i < n; i++) c[i] = (char)('0' + rng.Next(10)); return new string(c); }
        const string AN = "ABCDEFGHJKLMNPQRSTUVWXYZ0123456789";
        string alnum(int n) { var c = new char[n]; for (int i = 0; i < n; i++) c[i] = AN[rng.Next(AN.Length)]; return new string(c); }
        string mac() { var sb = new System.Text.StringBuilder("02"); for (int i = 0; i < 5; i++) { sb.Append(':'); sb.Append(rng.Next(256).ToString("x2")); } return sb.ToString(); }
        string inv(double d) => d.ToString("F6", System.Globalization.CultureInfo.InvariantCulture);

        var id = new RandId();
        string serial = "R" + digits(2) + alnum(9);
        string imei14 = "35" + digits(12);
        int sum = 0; for (int i = 0; i < 14; i++) { int dd = imei14[i] - '0'; if (i % 2 == 1) { dd *= 2; if (dd > 9) dd -= 9; } sum += dd; }
        string imei = imei14 + ((10 - (sum % 10)) % 10);
        string carrier = new[] { "Viettel", "Vinaphone", "Mobifone", "Vietnamobile" }[rng.Next(4)];
        string mnc = carrier == "Viettel" ? "04" : carrier == "Vinaphone" ? "02" : carrier == "Mobifone" ? "01" : "05";
        string mcc = "452";
        string imsi = mcc + mnc + digits(10);
        string iccid = "898404" + digits(13);
        string phone = "0" + "35789"[rng.Next(5)] + digits(8);
        string msisdn = "+84" + phone[1..];
        double lat = 8.5 + rng.NextDouble() * 15.0, lon = 102.1 + rng.NextDouble() * 7.5;
        string buildid = "TP1A." + digits(6) + "." + digits(3);
        string secpatch = $"20{rng.Next(21, 26)}-{rng.Next(1, 13):00}-{rng.Next(1, 29):00}";

        // Chỉ spoof định danh KHÔNG ảnh hưởng boot: serial/IMEI/MAC/SIM + model cosmetic.
        // GIỮ device/board/soc/platform/screen/fingerprint của S9 (không ghi đè) để máy còn boot.
        void set(string k, string v) => id.map[k] = v;
        set("SerialNo", serial); set("IMEI", imei); set("Meid", "A10000" + alnum(8));
        set("wifiMac", mac()); set("BSSID", mac()); set("wifiName", "DIRECT-" + alnum(4));
        set("PhoneNumber", phone); set("PhoneNumberMsisdn", msisdn);
        set("SimSerial", iccid); set("IccSerialNumber", iccid); set("SubscriberId", imsi);
        set("SimOperator", mcc + mnc); set("SimOperatorName", carrier);
        set("CountryCode", "VN"); set("csc", "XXV"); set("csciso", "XXV");
        set("model", s.model); set("brand", s.brand.ToLowerInvariant());
        set("lat", inv(lat)); set("lon", inv(lon));
        set("buildid", buildid); set("displayid", buildid);
        set("securitypatch", secpatch); set("secpatch", secpatch);
        set("release", androidVer.ToString()); set("sdkint", Sdk(androidVer)); set("oneui", "5.1");
        id.map["__lat__"] = inv(lat); id.map["__lon__"] = inv(lon);
        id.map["__brightness__"] = (80 + rng.Next(120)).ToString();
        return id;
    }
    static string Sdk(int a) => a switch { 14 => "34", 13 => "33", 12 => "32", 11 => "30", 10 => "29", _ => "33" };
}
