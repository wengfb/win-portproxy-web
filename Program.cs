using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

var host = GetConfiguredHost(args);
var port = GetConfiguredPort(args);
var settingsStore = new SettingsStore(Path.Combine(AppContext.BaseDirectory, "winportproxyweb.settings.json"));
var startupPassword = GetConfiguredPassword(args);
if (!string.IsNullOrWhiteSpace(startupPassword))
{
    settingsStore.SetPassword(startupPassword);
}

var auth = new AuthState(settingsStore);

var options = new WebApplicationOptions
{
    Args = args,
    ContentRootPath = AppContext.BaseDirectory
};

var builder = WebApplication.CreateBuilder(options);
builder.WebHost.UseUrls($"http://{host}:{port.ToString(CultureInfo.InvariantCulture)}");

var app = builder.Build();
var listenUrl = $"http://{host}:{port.ToString(CultureInfo.InvariantCulture)}";
var localUrl = $"http://127.0.0.1:{port.ToString(CultureInfo.InvariantCulture)}";

app.Use(async (context, next) =>
{
    var isLocalRequest = IsLocalRequest(context);
    if (!isLocalRequest && !settingsStore.Current.ExternalAccessEnabled)
    {
        context.Response.StatusCode = StatusCodes.Status403Forbidden;
        await context.Response.WriteAsJsonAsync(new ErrorResponse("外部访问尚未启用，请先在本机页面中开启。"));
        return;
    }

    if (!isLocalRequest &&
        context.Request.Path.StartsWithSegments("/api") &&
        !IsAuthExemptPath(context.Request.Path) &&
        !auth.IsAuthenticated(context))
    {
        context.Response.StatusCode = StatusCodes.Status401Unauthorized;
        await context.Response.WriteAsJsonAsync(new ErrorResponse("未登录或登录已过期"));
        return;
    }

    await next();
});

app.MapGet("/", (HttpContext context) => EmbeddedFile(context, "wwwroot/index.html", "text/html; charset=utf-8"));
app.MapGet("/index.html", (HttpContext context) => EmbeddedFile(context, "wwwroot/index.html", "text/html; charset=utf-8"));
app.MapGet("/app.js", (HttpContext context) => EmbeddedFile(context, "wwwroot/app.js", "application/javascript; charset=utf-8"));
app.MapGet("/styles.css", (HttpContext context) => EmbeddedFile(context, "wwwroot/styles.css", "text/css; charset=utf-8"));

app.MapGet("/api/status", (HttpContext context) => Results.Ok(new AppStatus(
    RuntimeInformation.OSDescription,
    RuntimeInformation.ProcessArchitecture.ToString(),
    IsAdministrator(),
    listenUrl,
    localUrl,
    settingsStore.Current.ExternalAccessEnabled,
    auth.Enabled,
    IsLocalRequest(context) || auth.IsAuthenticated(context),
    GetSuggestedUrls(port),
    IsAutoStartEnabled(),
    "双击启动后默认只允许本机管理。可在页面中开启外部访问，并一键创建管理面板防火墙规则。")));

app.MapPost("/api/login", (LoginRequest request, HttpContext context) =>
{
    if (!auth.Enabled)
    {
        return Results.Ok(new MessageResponse("未启用密码保护"));
    }

    if (!auth.TrySignIn(context, request.Password))
    {
        return Results.Unauthorized();
    }

    return Results.Ok(new MessageResponse("登录成功"));
});

app.MapPost("/api/logout", (HttpContext context) =>
{
    auth.SignOut(context);
    return Results.Ok(new MessageResponse("已退出登录"));
});

app.MapPost("/api/admin/access", (AdminAccessRequest request, HttpContext context) =>
{
    if (request.ExternalAccessEnabled && string.IsNullOrWhiteSpace(request.Password) && !settingsStore.Current.HasPassword)
    {
        return Results.BadRequest(new ErrorResponse("开启外部访问前必须设置管理密码。"));
    }

    if (!string.IsNullOrWhiteSpace(request.Password))
    {
        var trimmedPassword = request.Password.Trim();
        if (trimmedPassword.Length < 8)
        {
            return Results.BadRequest(new ErrorResponse("管理密码至少需要 8 位。"));
        }

        settingsStore.SetPassword(trimmedPassword);
        auth.SignIn(context);
    }

    settingsStore.SetExternalAccess(request.ExternalAccessEnabled);
    return Results.Ok(new AdminAccessResponse(
        "管理面板外部访问设置已保存。",
        settingsStore.Current.ExternalAccessEnabled,
        auth.Enabled,
        GetSuggestedUrls(port)));
});

app.MapPost("/api/admin/firewall/allow", async () =>
{
    var result = await EnsureAdminFirewallRule(port);
    return result.Success
        ? Results.Ok(new MessageResponse(result.Message))
        : Results.BadRequest(new ErrorResponse(result.Message));
});

app.MapPost("/api/admin/reset", (HttpContext context) =>
{
    settingsStore.Reset();
    auth.SignOut(context);
    return Results.Ok(new MessageResponse("管理面板配置已重置。外部访问已关闭，管理密码已清空。"));
});

app.MapPost("/api/admin/autostart", async (AutoStartRequest request) =>
{
    var result = request.Enabled
        ? await EnableAutoStart()
        : await DisableAutoStart();

    return result.Success
        ? Results.Ok(new AutoStartResponse(result.Message, IsAutoStartEnabled()))
        : Results.BadRequest(new ErrorResponse(result.Message));
});

app.MapGet("/api/rules", async () =>
{
    var result = await CommandRunner.RunAsync("netsh.exe", ["interface", "portproxy", "show", "v4tov4"]);
    if (!result.Success)
    {
        return CommandError(result, "读取 portproxy 规则失败");
    }

    return Results.Ok(ParsePortProxyRules(result.Output));
});

app.MapPost("/api/rules", async (PortProxyRuleRequest request) =>
{
    var validation = ValidateRule(request.ListenAddress, request.ListenPort, request.ConnectAddress, request.ConnectPort);
    if (validation is not null)
    {
        return Results.BadRequest(new ErrorResponse(validation));
    }

    var result = await AddPortProxyRule(request.ListenAddress, request.ListenPort, request.ConnectAddress, request.ConnectPort);
    return result.Success
        ? Results.Ok(new MessageResponse("端口转发规则已创建"))
        : CommandError(result, "创建 portproxy 规则失败");
});

app.MapDelete("/api/rules", async (string listenAddress, int listenPort) =>
{
    var validation = ValidateEndpoint(listenAddress, listenPort, nameof(listenAddress));
    if (validation is not null)
    {
        return Results.BadRequest(new ErrorResponse(validation));
    }

    var result = await CommandRunner.RunAsync("netsh.exe", [
        "interface", "portproxy", "delete", "v4tov4",
        $"listenaddress={listenAddress}",
        $"listenport={listenPort.ToString(CultureInfo.InvariantCulture)}"
    ]);

    return result.Success
        ? Results.Ok(new MessageResponse("端口转发规则已删除"))
        : CommandError(result, "删除 portproxy 规则失败");
});

app.MapGet("/api/wsl/distros", async () =>
{
    var quiet = await CommandRunner.RunAsync("wsl.exe", ["-l", "-q"]);
    if (!quiet.Success)
    {
        return Results.Ok(new WslDistrosResponse([], null, "未检测到 WSL 或 WSL 当前不可用。"));
    }

    var verbose = await CommandRunner.RunAsync("wsl.exe", ["-l", "-v"]);
    var defaultName = verbose.Success ? TryParseDefaultDistro(verbose.Output) : null;
    var distros = ParseQuietDistros(quiet.Output, defaultName).ToArray();
    var message = distros.Length == 0 ? "未检测到已安装的 WSL 发行版。" : null;

    return Results.Ok(new WslDistrosResponse(distros, defaultName, message));
});

app.MapGet("/api/wsl/ip", async (string? distro) =>
{
    var distroName = NormalizeOptional(distro);
    var ipResult = await GetWslIp(distroName);
    return ipResult.Error is null
        ? Results.Ok(new WslIpResponse(distroName, ipResult.IpAddress!))
        : Results.BadRequest(new ErrorResponse(ipResult.Error));
});

app.MapPost("/api/wsl/forward", async (WslForwardRequest request) =>
{
    var distroName = NormalizeOptional(request.Distro);
    var listenValidation = ValidateEndpoint("0.0.0.0", request.ListenPort, nameof(request.ListenPort));
    if (listenValidation is not null)
    {
        return Results.BadRequest(new ErrorResponse(listenValidation));
    }

    var targetValidation = ValidateEndpoint("127.0.0.1", request.TargetPort, nameof(request.TargetPort));
    if (targetValidation is not null)
    {
        return Results.BadRequest(new ErrorResponse(targetValidation));
    }

    var ipResult = await GetWslIp(distroName);
    if (ipResult.Error is not null)
    {
        return Results.BadRequest(new ErrorResponse(ipResult.Error));
    }

    var addResult = await AddPortProxyRule("0.0.0.0", request.ListenPort, ipResult.IpAddress!, request.TargetPort);
    if (!addResult.Success)
    {
        return CommandError(addResult, "创建 WSL 端口转发失败");
    }

    return Results.Ok(new WslForwardResponse(
        "WSL 端口转发规则已创建",
        distroName,
        "0.0.0.0",
        request.ListenPort,
        ipResult.IpAddress!,
        request.TargetPort));
});

app.MapPost("/api/firewall/allow", async (FirewallAllowRequest request) =>
{
    if (!IsValidPort(request.Port))
    {
        return Results.BadRequest(new ErrorResponse("端口必须在 1-65535 之间"));
    }

    var ruleName = string.IsNullOrWhiteSpace(request.Name)
        ? $"WinPortProxyWeb TCP {request.Port.ToString(CultureInfo.InvariantCulture)}"
        : request.Name.Trim();

    var result = await CommandRunner.RunAsync("netsh.exe", [
        "advfirewall", "firewall", "add", "rule",
        $"name={ruleName}",
        "dir=in",
        "action=allow",
        "protocol=TCP",
        $"localport={request.Port.ToString(CultureInfo.InvariantCulture)}"
    ]);

    return result.Success
        ? Results.Ok(new MessageResponse($"防火墙规则已创建：{ruleName}"))
        : CommandError(result, "创建防火墙规则失败");
});

app.Lifetime.ApplicationStarted.Register(() =>
{
    if (!HasFlag(args, "--no-browser") && Environment.GetEnvironmentVariable("WINPORTPROXYWEB_NO_BROWSER") != "1")
    {
        TryOpenBrowser(localUrl);
    }
});

app.Run();

static IResult EmbeddedFile(HttpContext context, string name, string contentType)
{
    var stream = Assembly.GetExecutingAssembly().GetManifestResourceStream(name);
    if (stream is null)
    {
        return Results.NotFound();
    }

    context.Response.Headers.CacheControl = "no-store, no-cache, must-revalidate";
    context.Response.Headers.Pragma = "no-cache";
    return Results.File(stream, contentType);
}

static async Task<CommandResult> AddPortProxyRule(string listenAddress, int listenPort, string connectAddress, int connectPort)
{
    return await CommandRunner.RunAsync("netsh.exe", [
        "interface", "portproxy", "add", "v4tov4",
        $"listenaddress={listenAddress}",
        $"listenport={listenPort.ToString(CultureInfo.InvariantCulture)}",
        $"connectaddress={connectAddress}",
        $"connectport={connectPort.ToString(CultureInfo.InvariantCulture)}"
    ]);
}


static async Task<FirewallResult> EnsureAdminFirewallRule(int port)
{
    var ruleName = $"WinPortProxyWeb Admin {port.ToString(CultureInfo.InvariantCulture)}";
    var show = await CommandRunner.RunAsync("netsh.exe", ["advfirewall", "firewall", "show", "rule", $"name={ruleName}"]);
    if (show.Success && show.Output.Contains(ruleName, StringComparison.OrdinalIgnoreCase))
    {
        return new FirewallResult(true, $"防火墙规则已存在：{ruleName}");
    }

    var add = await CommandRunner.RunAsync("netsh.exe", [
        "advfirewall", "firewall", "add", "rule",
        $"name={ruleName}",
        "dir=in",
        "action=allow",
        "protocol=TCP",
        $"localport={port.ToString(CultureInfo.InvariantCulture)}"
    ]);

    return add.Success
        ? new FirewallResult(true, $"防火墙规则已创建：{ruleName}")
        : new FirewallResult(false, FormatCommandFailure(add, "创建管理面板防火墙规则失败"));
}

static async Task<WslIpLookup> GetWslIp(string? distro)
{
    var args = new List<string>();
    if (!string.IsNullOrWhiteSpace(distro))
    {
        args.Add("-d");
        args.Add(distro);
    }

    args.Add("sh");
    args.Add("-lc");
    args.Add("hostname -I");

    var result = await CommandRunner.RunAsync("wsl.exe", args);
    if (!result.Success)
    {
        return new WslIpLookup(null, FormatCommandFailure(result, "获取 WSL IP 失败"));
    }

    var ip = ExtractFirstIpv4(result.Output);
    return ip is null
        ? new WslIpLookup(null, "没有从 WSL 输出中找到 IPv4 地址")
        : new WslIpLookup(ip, null);
}

static IResult CommandError(CommandResult result, string fallbackMessage)
{
    return Results.BadRequest(new ErrorResponse(FormatCommandFailure(result, fallbackMessage)));
}

static string FormatCommandFailure(CommandResult result, string fallbackMessage)
{
    var message = string.IsNullOrWhiteSpace(result.Error) ? result.Output : result.Error;
    return string.IsNullOrWhiteSpace(message)
        ? fallbackMessage
        : $"{fallbackMessage}: {message.Trim()}";
}

static string? ValidateRule(string listenAddress, int listenPort, string connectAddress, int connectPort)
{
    return ValidateEndpoint(listenAddress, listenPort, nameof(listenAddress))
        ?? ValidateEndpoint(connectAddress, connectPort, nameof(connectAddress));
}

static string? ValidateEndpoint(string address, int port, string fieldName)
{
    if (!IsValidIpv4(address))
    {
        return $"{fieldName} 必须是有效 IPv4 地址";
    }

    return IsValidPort(port) ? null : "端口必须在 1-65535 之间";
}

static bool IsValidIpv4(string value)
{
    return IPAddress.TryParse(value, out var address) && address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork;
}

static bool IsValidPort(int port) => port is >= 1 and <= 65535;

static string? NormalizeOptional(string? value) => string.IsNullOrWhiteSpace(value) ? null : value.Trim();

static string? ExtractFirstIpv4(string output)
{
    foreach (Match match in Regex.Matches(output, @"\b(?:\d{1,3}\.){3}\d{1,3}\b"))
    {
        if (IsValidIpv4(match.Value))
        {
            return match.Value;
        }
    }

    return null;
}

static IReadOnlyList<PortProxyRule> ParsePortProxyRules(string output)
{
    var rules = new List<PortProxyRule>();
    foreach (var line in SplitLines(output))
    {
        var parts = Regex.Split(line.Trim(), @"\s+").Where(p => p.Length > 0).ToArray();
        if (parts.Length != 4)
        {
            continue;
        }

        if (!IsValidIpv4(parts[0]) || !int.TryParse(parts[1], out var listenPort) ||
            !IsValidIpv4(parts[2]) || !int.TryParse(parts[3], out var connectPort))
        {
            continue;
        }

        rules.Add(new PortProxyRule(parts[0], listenPort, parts[2], connectPort, GuessRuleSource(parts[0], parts[2])));
    }

    return rules;
}

static string GuessRuleSource(string listenAddress, string connectAddress)
{
    return listenAddress == "0.0.0.0" && !IPAddress.IsLoopback(IPAddress.Parse(connectAddress))
        ? "可能是 WSL/局域网转发"
        : "普通规则";
}

static IReadOnlyList<WslDistro> ParseQuietDistros(string output, string? defaultName)
{
    return SplitLines(output)
        .Select(line => line.Trim().TrimStart('*').Trim())
        .Where(line => !string.IsNullOrWhiteSpace(line))
        .Select(line => new WslDistro(line, string.Equals(line, defaultName, StringComparison.OrdinalIgnoreCase)))
        .ToArray();
}

static string? TryParseDefaultDistro(string output)
{
    foreach (var line in SplitLines(output))
    {
        var trimmed = line.Trim();
        if (!trimmed.StartsWith('*'))
        {
            continue;
        }

        var withoutMarker = trimmed.TrimStart('*').Trim();
        var match = Regex.Match(withoutMarker, @"^(?<name>.+?)\s{2,}\S+");
        return match.Success ? match.Groups["name"].Value.Trim() : withoutMarker.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault();
    }

    return null;
}

static bool IsAdministrator()
{
    if (!OperatingSystem.IsWindows())
    {
        return false;
    }

    using var identity = WindowsIdentity.GetCurrent();
    var principal = new WindowsPrincipal(identity);
    return principal.IsInRole(WindowsBuiltInRole.Administrator);
}

static IEnumerable<string> SplitLines(string value)
{
    return value.Replace("\0", string.Empty).Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
}


static string GetConfiguredHost(string[] args)
{
    return NormalizeOptional(GetOption(args, "--host"))
        ?? NormalizeOptional(Environment.GetEnvironmentVariable("WINPORTPROXYWEB_HOST"))
        ?? "0.0.0.0";
}

static int GetConfiguredPort(string[] args)
{
    var value = NormalizeOptional(GetOption(args, "--port"))
        ?? NormalizeOptional(Environment.GetEnvironmentVariable("WINPORTPROXYWEB_PORT"));

    if (value is null)
    {
        return 5179;
    }

    if (!int.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out var port) || !IsValidPort(port))
    {
        throw new InvalidOperationException("端口必须在 1-65535 之间。");
    }

    return port;
}

static string? GetConfiguredPassword(string[] args)
{
    return NormalizeOptional(GetOption(args, "--password"))
        ?? NormalizeOptional(Environment.GetEnvironmentVariable("WINPORTPROXYWEB_PASSWORD"));
}

static string? GetOption(string[] args, string name)
{
    for (var i = 0; i < args.Length; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
        {
            return args[i + 1];
        }

        var prefix = name + "=";
        if (args[i].StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
        {
            return args[i][prefix.Length..];
        }
    }

    return null;
}

static bool HasFlag(string[] args, string name)
{
    return args.Any(arg => string.Equals(arg, name, StringComparison.OrdinalIgnoreCase));
}

static bool IsLocalRequest(HttpContext context)
{
    var remote = context.Connection.RemoteIpAddress;
    if (remote is null)
    {
        return true;
    }

    if (remote.IsIPv4MappedToIPv6)
    {
        remote = remote.MapToIPv4();
    }

    return IPAddress.IsLoopback(remote);
}

static void TryOpenBrowser(string url)
{
    try
    {
        Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
    }
    catch
    {
    }
}

static IReadOnlyList<AccessUrl> GetSuggestedUrls(int port)
{
    var urls = new List<AccessUrl>
    {
        new("本机", $"http://127.0.0.1:{port.ToString(CultureInfo.InvariantCulture)}", false)
    };

    foreach (var networkInterface in NetworkInterface.GetAllNetworkInterfaces())
    {
        if (networkInterface.OperationalStatus != OperationalStatus.Up)
        {
            continue;
        }

        foreach (var address in networkInterface.GetIPProperties().UnicastAddresses)
        {
            if (address.Address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork || IPAddress.IsLoopback(address.Address))
            {
                continue;
            }

            var ip = address.Address.ToString();
            var isTailscale = networkInterface.Name.Contains("Tailscale", StringComparison.OrdinalIgnoreCase) || ip.StartsWith("100.", StringComparison.Ordinal);
            urls.Add(new AccessUrl(networkInterface.Name, $"http://{ip}:{port.ToString(CultureInfo.InvariantCulture)}", isTailscale));
        }
    }

    return urls
        .GroupBy(url => url.Url, StringComparer.OrdinalIgnoreCase)
        .Select(group => group.First())
        .OrderByDescending(url => url.IsTailscale)
        .ThenBy(url => url.Name, StringComparer.OrdinalIgnoreCase)
        .ToArray();
}

static bool IsAuthExemptPath(PathString path)
{
    return path.Equals("/api/status", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/api/login", StringComparison.OrdinalIgnoreCase)
        || path.Equals("/api/logout", StringComparison.OrdinalIgnoreCase);
}


static bool IsAutoStartEnabled()
{
    var result = CommandRunner.Run("schtasks.exe", ["/Query", "/TN", AutoStartTaskName()]);
    return result.Success;
}

static async Task<AutoStartResult> EnableAutoStart()
{
    var exePath = Environment.ProcessPath ?? Process.GetCurrentProcess().MainModule?.FileName;
    if (string.IsNullOrWhiteSpace(exePath))
    {
        return new AutoStartResult(false, "无法确定当前 exe 路径。");
    }

    var command = $"\\\"{exePath}\\\" --no-browser";
    var result = await CommandRunner.RunAsync("schtasks.exe", [
        "/Create",
        "/TN", AutoStartTaskName(),
        "/SC", "ONLOGON",
        "/TR", command,
        "/F"
    ]);

    return result.Success
        ? new AutoStartResult(true, "开机自启已启用。")
        : new AutoStartResult(false, FormatCommandFailure(result, "启用开机自启失败"));
}

static async Task<AutoStartResult> DisableAutoStart()
{
    var result = await CommandRunner.RunAsync("schtasks.exe", ["/Delete", "/TN", AutoStartTaskName(), "/F"]);
    if (result.Success)
    {
        return new AutoStartResult(true, "开机自启已禁用。");
    }

    if ((result.Output + result.Error).Contains("ERROR: The system cannot find", StringComparison.OrdinalIgnoreCase))
    {
        return new AutoStartResult(true, "开机自启已禁用。");
    }

    return new AutoStartResult(false, FormatCommandFailure(result, "禁用开机自启失败"));
}

static string AutoStartTaskName() => "WinPortProxyWeb";

static class CommandRunner
{
    public static CommandResult Run(string fileName, IEnumerable<string> arguments)
    {
        return RunAsync(fileName, arguments).GetAwaiter().GetResult();
    }

    public static async Task<CommandResult> RunAsync(string fileName, IEnumerable<string> arguments)
    {
        try
        {
            var startInfo = new ProcessStartInfo(fileName)
            {
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
                StandardOutputEncoding = Encoding.UTF8,
                StandardErrorEncoding = Encoding.UTF8
            };

            foreach (var argument in arguments)
            {
                startInfo.ArgumentList.Add(argument);
            }

            using var process = Process.Start(startInfo);
            if (process is null)
            {
                return new CommandResult(-1, string.Empty, $"无法启动命令：{fileName}");
            }

            var outputTask = process.StandardOutput.ReadToEndAsync();
            var errorTask = process.StandardError.ReadToEndAsync();
            await process.WaitForExitAsync();

            return new CommandResult(process.ExitCode, await outputTask, await errorTask);
        }
        catch (Exception ex) when (ex is InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return new CommandResult(-1, string.Empty, ex.Message);
        }
    }
}




sealed class SettingsStore
{
    private const int DefaultPasswordIterations = 100_000;
    private readonly object gate = new();
    private readonly string path;
    private AdminSettings current;

    public SettingsStore(string path)
    {
        this.path = path;
        current = Load(path);
    }

    public AdminSettings Current
    {
        get
        {
            lock (gate)
            {
                return current.Clone();
            }
        }
    }

    public void SetExternalAccess(bool enabled)
    {
        lock (gate)
        {
            current.ExternalAccessEnabled = enabled;
            Save();
        }
    }

    public void SetPassword(string password)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var hash = HashPassword(password, salt, DefaultPasswordIterations);

        lock (gate)
        {
            current.PasswordSalt = Convert.ToBase64String(salt);
            current.PasswordHash = Convert.ToBase64String(hash);
            current.PasswordIterations = DefaultPasswordIterations;
            Save();
        }
    }

    public void Reset()
    {
        lock (gate)
        {
            current = new AdminSettings();
            Save();
        }
    }

    public bool VerifyPassword(string password)
    {
        AdminSettings snapshot;
        lock (gate)
        {
            snapshot = current.Clone();
        }

        if (!snapshot.HasPassword || snapshot.PasswordSalt is null || snapshot.PasswordHash is null)
        {
            return false;
        }

        var salt = Convert.FromBase64String(snapshot.PasswordSalt);
        var expected = Convert.FromBase64String(snapshot.PasswordHash);
        var actual = HashPassword(password, salt, snapshot.PasswordIterations);
        return expected.Length == actual.Length && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    private static AdminSettings Load(string path)
    {
        if (!File.Exists(path))
        {
            return new AdminSettings();
        }

        try
        {
            return JsonSerializer.Deserialize<AdminSettings>(File.ReadAllText(path, Encoding.UTF8)) ?? new AdminSettings();
        }
        catch
        {
            return new AdminSettings();
        }
    }

    private void Save()
    {
        var json = JsonSerializer.Serialize(current, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json, Encoding.UTF8);
    }

    private static byte[] HashPassword(string password, byte[] salt, int iterations)
    {
        return Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, HashAlgorithmName.SHA256, 32);
    }
}

sealed class AuthState
{
    private const string CookieName = "wppw_session";
    private readonly SettingsStore settingsStore;
    private string sessionToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));

    public AuthState(SettingsStore settingsStore)
    {
        this.settingsStore = settingsStore;
    }

    public bool Enabled => settingsStore.Current.HasPassword;

    public bool TrySignIn(HttpContext context, string password)
    {
        if (!Enabled || !settingsStore.VerifyPassword(password))
        {
            return false;
        }

        SignIn(context);
        return true;
    }

    public void SignIn(HttpContext context)
    {
        sessionToken = Convert.ToHexString(RandomNumberGenerator.GetBytes(32));
        context.Response.Cookies.Append(CookieName, sessionToken, new CookieOptions
        {
            HttpOnly = true,
            SameSite = SameSiteMode.Lax,
            Path = "/"
        });
    }

    public bool IsAuthenticated(HttpContext context)
    {
        if (!Enabled)
        {
            return true;
        }

        return context.Request.Cookies.TryGetValue(CookieName, out var value)
            && FixedTimeEquals(sessionToken, value);
    }

    public void SignOut(HttpContext context)
    {
        context.Response.Cookies.Delete(CookieName);
    }

    private static bool FixedTimeEquals(string expected, string actual)
    {
        var expectedBytes = Encoding.UTF8.GetBytes(expected);
        var actualBytes = Encoding.UTF8.GetBytes(actual);
        return expectedBytes.Length == actualBytes.Length && CryptographicOperations.FixedTimeEquals(expectedBytes, actualBytes);
    }
}

sealed class AdminSettings
{
    public bool ExternalAccessEnabled { get; set; }
    public string? PasswordHash { get; set; }
    public string? PasswordSalt { get; set; }
    public int PasswordIterations { get; set; } = 100_000;
    public bool HasPassword => !string.IsNullOrWhiteSpace(PasswordHash) && !string.IsNullOrWhiteSpace(PasswordSalt);

    public AdminSettings Clone()
    {
        return new AdminSettings
        {
            ExternalAccessEnabled = ExternalAccessEnabled,
            PasswordHash = PasswordHash,
            PasswordSalt = PasswordSalt,
            PasswordIterations = PasswordIterations
        };
    }
}

record CommandResult(int ExitCode, string Output, string Error)
{
    public bool Success => ExitCode == 0;
}

record AppStatus(
    string OsDescription,
    string Architecture,
    bool IsAdministrator,
    string ListenUrl,
    string LocalUrl,
    bool ExternalAccessEnabled,
    bool AuthenticationEnabled,
    bool Authenticated,
    IReadOnlyList<AccessUrl> AccessUrls,
    bool AutoStartEnabled,
    string Message);
record AccessUrl(string Name, string Url, bool IsTailscale);
record AdminAccessRequest(bool ExternalAccessEnabled, string? Password);
record AutoStartRequest(bool Enabled);
record AutoStartResponse(string Message, bool Enabled);
record AutoStartResult(bool Success, string Message);
record AdminAccessResponse(string Message, bool ExternalAccessEnabled, bool AuthenticationEnabled, IReadOnlyList<AccessUrl> AccessUrls);
record FirewallResult(bool Success, string Message);
record LoginRequest(string Password);
record PortProxyRule(string ListenAddress, int ListenPort, string ConnectAddress, int ConnectPort, string Source);
record PortProxyRuleRequest(string ListenAddress, int ListenPort, string ConnectAddress, int ConnectPort);
record WslDistro(string Name, bool IsDefault);
record WslDistrosResponse(IReadOnlyList<WslDistro> Distros, string? DefaultDistro, string? Message);
record WslIpResponse(string? Distro, string IpAddress);
record WslIpLookup(string? IpAddress, string? Error);
record WslForwardRequest(string? Distro, int ListenPort, int TargetPort);
record WslForwardResponse(string Message, string? Distro, string ListenAddress, int ListenPort, string ConnectAddress, int ConnectPort);
record FirewallAllowRequest(int Port, string? Name);
record MessageResponse(string Message);
record ErrorResponse(string Error);
