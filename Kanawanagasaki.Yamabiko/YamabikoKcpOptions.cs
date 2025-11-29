namespace Kanawanagasaki.Yamabiko;

public record YamabikoKcpOptions
{
    public bool ReliableNoDelay { get; init; } = true;
    public int ReliableIntervalMs { get; init; } = 10;
    public int ReliableFastResend { get; init; } = 2;
    public bool ReliableNoCongestionControl { get; init; } = false;
    public int ReliableSendWindowSize { get; init; } = 128;
    public int ReliableRecvWindowSize { get; init; } = 256;
    public int ReliableMtu { get; init; } = 1300;

    public bool StreamNoDelay { get; init; } = false;
    public int StreamIntervalMs { get; init; } = 40;
    public int StreamFastResend { get; init; } = 0;
    public bool StreamNoCongestionControl { get; init; } = false;
    public int StreamSendWindowSize { get; init; } = 256;
    public int StreamRecvWindowSize { get; init; } = 512;
    public int StreamMtu { get; init; } = 1300;
}
