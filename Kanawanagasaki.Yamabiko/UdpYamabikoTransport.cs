namespace Kanawanagasaki.Yamabiko;

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

internal class UdpYamabikoTransport : YamabikoTransport
{
    private UdpClient? _client;

    protected override void Init()
    {
        _client = new UdpClient(new IPEndPoint(IPAddress.Any, 0));
    }

    public override async Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        await _client!.SendAsync(buffer, endpoint, ct);
    }

    protected override async Task<YamabikoReceiveResult> ReceiveAsync(CancellationToken ct)
    {
        var result = await _client!.ReceiveAsync(ct);
        return new YamabikoReceiveResult(result.Buffer, result.RemoteEndPoint);
    }

    public override ushort GetLanPort()
        => (ushort)((_client!.Client.LocalEndPoint as IPEndPoint)?.Port ?? 0);

    public override async ValueTask DisposeAsync()
    {
        _client!.Dispose();
        await base.DisposeAsync();
    }
}
