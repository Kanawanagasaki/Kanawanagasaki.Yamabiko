namespace Kanawanagasaki.Yamabiko;

public class PeerConnectResult
{
    public bool IsAccepted { get; }
    public string? Reason { get; }

    private PeerConnectResult(bool isAccepted)
    {
        IsAccepted = isAccepted;
    }

    private PeerConnectResult(string? reason)
    {
        IsAccepted = false;
        Reason = reason;
    }

    public static PeerConnectResult Accept()
        => new PeerConnectResult(true);

    public static PeerConnectResult Deny(string? reason)
        => new PeerConnectResult(reason);
}
