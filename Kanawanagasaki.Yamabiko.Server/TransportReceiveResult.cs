namespace Kanawanagasaki.Yamabiko.Server;

using System.Net;

public struct TransportReceiveResult
{
    public ReadOnlyMemory<byte> Buffer { get; }
    public IPEndPoint RemoteEndPoint { get; }

    public TransportReceiveResult(ReadOnlyMemory<byte> buffer, IPEndPoint remoteEndPoint)
    {
        Buffer = buffer;
        RemoteEndPoint = remoteEndPoint;
    }
}
