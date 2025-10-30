namespace Kanawanagasaki.Yamabiko.Server;

using System.Net;

public interface ITransport : IDisposable
{
    Task<TransportReceiveResult> ReceiveAsync(CancellationToken ct);
    Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct);
}
