namespace Kanawanagasaki.Yamabiko.Server;

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

public class UdpTransport : ITransport
{
    private readonly Settings _settings;
    private readonly UdpClient _udp;

    public UdpTransport(Settings settings)
    {
        _settings = settings;
        _udp = new UdpClient(_settings.Port);
    }

    public async Task<TransportReceiveResult> ReceiveAsync(CancellationToken ct)
    {
        var result = await _udp.ReceiveAsync(ct);
        return new TransportReceiveResult(result.Buffer, result.RemoteEndPoint);
    }

    public async Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        await _udp.SendAsync(buffer, endpoint, ct);
    }

    public void Dispose()
    {
        _udp.Dispose();
    }
}
