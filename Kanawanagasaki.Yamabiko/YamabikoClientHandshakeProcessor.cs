namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls.Handshake;
using System;
using System.Threading;
using System.Threading.Tasks;

public class YamabikoClientHandshakeProcessor : ClientHandshakeProcessor
{
    private readonly YamabikoClient _client;
    private readonly YamabikoTransport _transport;

    public YamabikoClientHandshakeProcessor(YamabikoClient client, YamabikoTransport transport)
    {
        _client = client;
        _transport = transport;
    }

    protected override int PacketMtu()
        => 1400;

    protected override string RendezvousServerDomain()
        => _client.CertificateDomain ?? "example.com";

    protected override async Task<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct)
        => await _transport.ReceiveFromEndpointAsync(_client.ServerEndPoint, ct);

    protected override async Task SendAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
        => await _client.SendBufferAsync(_client.ServerEndPoint, buffer, ct);
}
