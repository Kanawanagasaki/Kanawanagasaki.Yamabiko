using Kanawanagasaki.Yamabiko.Server;

Console.WriteLine("-= Yamabiko =-");

var parsedArgs = ParseArgs(args);

if (GetSettingValue(parsedArgs, nameof(Settings.Domain)) is string domain)
    Settings.Domain = domain;
if (GetSettingValue(parsedArgs, nameof(Settings.Port)) is string portStr && int.TryParse(portStr, out var port))
    Settings.Port = port;
if (GetSettingValue(parsedArgs, nameof(Settings.MTU)) is string mtuStr && int.TryParse(mtuStr, out var mtu))
    Settings.MTU = mtu;
if (GetSettingValue(parsedArgs, nameof(Settings.CertificatePath)) is string certificatePath)
    Settings.CertificatePath = certificatePath;
if (GetSettingValue(parsedArgs, nameof(Settings.MaxClients)) is string maxClientsStr && int.TryParse(maxClientsStr, out var maxClients))
    Settings.MaxClients = maxClients;
if (GetSettingValue(parsedArgs, nameof(Settings.MaxClientsPerRemoteNetwork)) is string maxClientsPerRemoteNetworkStr && int.TryParse(maxClientsPerRemoteNetworkStr, out var maxClientsPerRemoteNetwork))
    Settings.MaxClientsPerRemoteNetwork = maxClientsPerRemoteNetwork;
if (GetSettingValue(parsedArgs, nameof(Settings.MaxInactivitySeconds)) is string maxInactivitySecondsStr && int.TryParse(maxInactivitySecondsStr, out var maxInactivitySeconds))
    Settings.MaxInactivitySeconds = maxInactivitySeconds;

Console.WriteLine($"{Settings.Domain}:{Settings.Port}");

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (sender, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var udpServiceTask = UdpService.RunAsync(cts.Token);
var clientsClearTask = ClientsService.RunClearTimerAsync(cts.Token);

await Task.WhenAll(udpServiceTask, clientsClearTask);

static string? GetSettingValue(Dictionary<string, string> parsedArgs, string key)
{
    if (parsedArgs.ContainsKey(key.ToLowerInvariant()))
        return parsedArgs[key];
    return Environment.GetEnvironmentVariable(nameof(Kanawanagasaki.Yamabiko).ToUpperInvariant() + "_" + key.ToUpperInvariant());
}

static Dictionary<string, string> ParseArgs(string[] args)
{
    var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

    for (int i = 0; i < args.Length; i++)
    {
        var a = args[i];
        if (!a.StartsWith('-'))
            continue;

        var key = a.TrimStart('-');

        var eqIndex = key.IndexOf('=');
        if (eqIndex >= 0)
        {
            var k = NormalizeKey(key.Substring(0, eqIndex));
            var v = key.Substring(eqIndex + 1);
            if (!string.IsNullOrEmpty(k))
                result[k] = v;
            continue;
        }

        string? val = null;
        if (i + 1 < args.Length && !args[i + 1].StartsWith('-'))
        {
            val = args[i + 1];
            i++;
        }

        var nkey = NormalizeKey(key);
        if (!string.IsNullOrEmpty(nkey) && val is not null)
            result[nkey] = val;
    }

    return result;
}

static string NormalizeKey(string key)
    => key.Replace("-", "", StringComparison.Ordinal)
          .Replace("_", "", StringComparison.Ordinal)
          .ToLowerInvariant();
