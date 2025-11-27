namespace Kanawanagasaki.Yamabiko;

public record YamabikoKcpOptions
{
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
}
