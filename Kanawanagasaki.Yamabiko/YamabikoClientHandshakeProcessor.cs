namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls.Handshake;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

public class YamabikoClientHandshakeProcessor : ClientHandshakeProcessor
{
    private readonly YamabikoClient _client;
    private readonly YamabikoTransport _transport;
    private readonly YamabikoClient.ValidateCertificatesDelegate? _validateCert;

    public YamabikoClientHandshakeProcessor(YamabikoClient client, YamabikoTransport transport, YamabikoClient.ValidateCertificatesDelegate? validateCert)
    {
        _client = client;
        _transport = transport;
        _validateCert = validateCert;
    }

    protected override int PacketMtu()
        => 1400;

    protected override string RendezvousServerDomain()
        => _client.CertificateDomain ?? "example.com";

    protected override async Task<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct)
        => await _transport.ReceiveFromEndpointAsync(_client.ServerEndPoint, ct);

    protected override async Task SendAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
        => await _client.SendBufferAsync(_client.ServerEndPoint, buffer, ct);

    protected override bool ValidateCertificates(X509Certificate2[] certificates, string domain)
        => _validateCert is null ? base.ValidateCertificates(certificates, domain) : _validateCert(certificates, domain);
}
