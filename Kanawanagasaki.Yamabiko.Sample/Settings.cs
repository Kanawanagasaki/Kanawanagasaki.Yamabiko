namespace Kanawanagasaki.Yamabiko.Sample;

using System.Text.Json;
using System.Text.Json.Serialization;

public class AppSettings
{
    private static readonly string SettingsPath = Path.Combine(AppContext.BaseDirectory, "settings.json");

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public string ServerIp { get; set; } = "127.0.0.1";
    public int ServerPort { get; set; } = 9999;
    public string ServerDomain { get; set; } = "";
    public string ProjectId { get; set; } = "7029bc66-f478-44cf-aaea-94d55d2365fb";

    public string HostName { get; set; } = "";
    public string JoinName { get; set; } = "";
    public string HostPassword { get; set; } = "";

    public bool ReliableNoDelay { get; set; } = true;
    public int ReliableIntervalMs { get; set; } = 10;
    public int ReliableFastResend { get; set; } = 2;
    public bool ReliableNoCongestionControl { get; set; } = false;
    public int ReliableSendWindowSize { get; set; } = 128;
    public int ReliableRecvWindowSize { get; set; } = 256;
    public int ReliableMtu { get; set; } = 1300;

    public bool StreamNoDelay { get; set; } = false;
    public int StreamIntervalMs { get; set; } = 40;
    public int StreamFastResend { get; set; } = 0;
    public bool StreamNoCongestionControl { get; set; } = false;
    public int StreamSendWindowSize { get; set; } = 256;
    public int StreamRecvWindowSize { get; set; } = 512;
    public int StreamMtu { get; set; } = 1300;

    public static AppSettings Load()
    {
        try
        {
            if (File.Exists(SettingsPath))
            {
                var json = File.ReadAllText(SettingsPath);
                var settings = JsonSerializer.Deserialize<AppSettings>(json, JsonOptions);
                if (settings is not null)
                    return settings;
            }
        }
        catch { }

        return new AppSettings();
    }

    public void Save()
    {
        try
        {
            var json = JsonSerializer.Serialize(this, JsonOptions);
            File.WriteAllText(SettingsPath, json);
        }
        catch { }
    }

    public YamabikoKcpOptions ToKcpOptions()
        => new YamabikoKcpOptions
        {
            ReliableNoDelay = ReliableNoDelay,
            ReliableIntervalMs = ReliableIntervalMs,
            ReliableFastResend = ReliableFastResend,
            ReliableNoCongestionControl = ReliableNoCongestionControl,
            ReliableSendWindowSize = ReliableSendWindowSize,
            ReliableRecvWindowSize = ReliableRecvWindowSize,
            ReliableMtu = ReliableMtu,
            StreamNoDelay = StreamNoDelay,
            StreamIntervalMs = StreamIntervalMs,
            StreamFastResend = StreamFastResend,
            StreamNoCongestionControl = StreamNoCongestionControl,
            StreamSendWindowSize = StreamSendWindowSize,
            StreamRecvWindowSize = StreamRecvWindowSize,
            StreamMtu = StreamMtu,
        };

    public static AppSettings FromKcpOptions(YamabikoKcpOptions kcp, string serverIp, int serverPort, string serverDomain, string projectId, string hostName, string joinName, string hostPassword = "")
        => new AppSettings
        {
            ServerIp = serverIp,
            ServerPort = serverPort,
            ServerDomain = serverDomain,
            ProjectId = projectId,
            HostName = hostName,
            JoinName = joinName,
            HostPassword = hostPassword,
            ReliableNoDelay = kcp.ReliableNoDelay,
            ReliableIntervalMs = kcp.ReliableIntervalMs,
            ReliableFastResend = kcp.ReliableFastResend,
            ReliableNoCongestionControl = kcp.ReliableNoCongestionControl,
            ReliableSendWindowSize = kcp.ReliableSendWindowSize,
            ReliableRecvWindowSize = kcp.ReliableRecvWindowSize,
            ReliableMtu = kcp.ReliableMtu,
            StreamNoDelay = kcp.StreamNoDelay,
            StreamIntervalMs = kcp.StreamIntervalMs,
            StreamFastResend = kcp.StreamFastResend,
            StreamNoCongestionControl = kcp.StreamNoCongestionControl,
            StreamSendWindowSize = kcp.StreamSendWindowSize,
            StreamRecvWindowSize = kcp.StreamRecvWindowSize,
            StreamMtu = kcp.StreamMtu,
        };
}
