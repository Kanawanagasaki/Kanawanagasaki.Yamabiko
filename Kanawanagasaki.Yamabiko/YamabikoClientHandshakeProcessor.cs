namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls.Handshake;
using System;
using System.Threading;
using System.Threading.Tasks;

public class YamabikoClientHandshakeProcessor : ClientHandshakeProcessor
{
    private readonly YamabikoClient _client;

    public YamabikoClientHandshakeProcessor(YamabikoClient client)
    {
        _client = client;
    }

    protected override int PacketMtu()
        => 1400;

    protected override string RendezvousServerDomain()
        => _client.CertificateDomain ?? "example.com";

    protected override async Task<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct)
    {
        var result = await _client.Udp.ReceiveAsync(ct);
        if (result.RemoteEndPoint.Equals(_client.ServerEndPoint))
            return result.Buffer;
        return Array.Empty<byte>();
    }

    protected override async Task SendAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
        => await _client.Udp.SendAsync(buffer, _client.ServerEndPoint, ct);
}
