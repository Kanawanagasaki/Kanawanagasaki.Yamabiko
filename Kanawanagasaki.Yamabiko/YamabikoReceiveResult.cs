namespace Kanawanagasaki.Yamabiko;

using System.Net;

public struct YamabikoReceiveResult
{
    public ReadOnlyMemory<byte> Buffer { get; }
    public IPEndPoint RemoteEndPoint { get; }

    public YamabikoReceiveResult(ReadOnlyMemory<byte> buffer, IPEndPoint remoteEndPoint)
    {
        Buffer = buffer;
        RemoteEndPoint = remoteEndPoint;
    }
}
