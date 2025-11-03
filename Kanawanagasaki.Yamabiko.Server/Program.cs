using Kanawanagasaki.Yamabiko.Server;

Console.WriteLine("-= Yamabiko =-");

var parsedArgs = ParseArgs(args);

var settings = new Settings();

if (GetSettingValue(parsedArgs, nameof(Settings.Domain)) is string domain)
    settings.Domain = domain;
if (GetSettingValue(parsedArgs, nameof(Settings.Port)) is string portStr && int.TryParse(portStr, out var port))
    settings.Port = port;
if (GetSettingValue(parsedArgs, nameof(Settings.MTU)) is string mtuStr && int.TryParse(mtuStr, out var mtu))
    settings.MTU = mtu;
if (GetSettingValue(parsedArgs, nameof(Settings.CertificatePath)) is string certificatePath)
    settings.CertificatePath = certificatePath;
if (GetSettingValue(parsedArgs, nameof(Settings.MaxClients)) is string maxClientsStr && int.TryParse(maxClientsStr, out var maxClients))
    settings.MaxClients = maxClients;
if (GetSettingValue(parsedArgs, nameof(Settings.MaxClientsPerRemoteNetwork)) is string maxClientsPerRemoteNetworkStr && int.TryParse(maxClientsPerRemoteNetworkStr, out var maxClientsPerRemoteNetwork))
    settings.MaxClientsPerRemoteNetwork = maxClientsPerRemoteNetwork;
if (GetSettingValue(parsedArgs, nameof(Settings.MaxInactivitySeconds)) is string maxInactivitySecondsStr && int.TryParse(maxInactivitySecondsStr, out var maxInactivitySeconds))
    settings.MaxInactivitySeconds = maxInactivitySeconds;

Console.WriteLine($"{settings.Domain}:{settings.Port}");

var cts = new CancellationTokenSource();
Console.CancelKeyPress += (sender, e) =>
{
    e.Cancel = true;
    cts.Cancel();
};

var transport = new UdpTransport(settings);

var projectsService = new ProjectsService();

var clientsService = new ClientsService(settings, transport, projectsService);
var clientsClearTask = clientsService.RunClearTimerAsync(cts.Token);

var receiveService = new ReceiverService(clientsService, transport);
var receiveServiceTask = receiveService.RunAsync(cts.Token);

await Task.WhenAll(clientsClearTask, receiveServiceTask);

transport.Dispose();

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
