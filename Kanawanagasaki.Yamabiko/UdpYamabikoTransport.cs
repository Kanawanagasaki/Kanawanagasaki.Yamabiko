namespace Kanawanagasaki.Yamabiko;

using System;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;

internal class UdpYamabikoTransport : YamabikoTransport
{
    internal UdpClient Client { get; }

    internal UdpYamabikoTransport()
    {
        Client = new UdpClient();
    }

    internal UdpYamabikoTransport(IPEndPoint endpoint)
    {
        Client = new UdpClient(endpoint);
    }

    public override async Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        await Client.SendAsync(buffer, endpoint, ct);
    }

    protected override async Task<YamabikoReceiveResult> ReceiveAsync(CancellationToken ct)
    {
        var result = await Client.ReceiveAsync(ct);
        return new YamabikoReceiveResult(result.Buffer, result.RemoteEndPoint);
    }

    public override async ValueTask DisposeAsync()
    {
        Client.Dispose();
        await base.DisposeAsync();
    }
}
