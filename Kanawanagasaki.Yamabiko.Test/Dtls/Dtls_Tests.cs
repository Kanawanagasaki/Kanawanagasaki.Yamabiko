namespace Kanawanagasaki.Yamabiko.Test.Dtls;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Handshake;
using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using System;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using Xunit.Abstractions;

public class Dtls_Tests(ITestOutputHelper _output)
{
    [Theory]
    [InlineData(0xFFFF)]
    [InlineData(1400)]
    [InlineData(1024)]
    [InlineData(512)]
    [InlineData(256)]
    [InlineData(128)]
    [InlineData(64)]
    public async Task Handshake_100Percent_Ordered_SingleRecordInPacket(int mtu)
    {
        var domain = "example.com";
        using var certificate = CertificateHelper.GenerateSelfSignedCertificate(domain);

        var serverProcessor = new ServerHandshakeProcessor(certificate, mtu);

        var packetsFromServer = new List<byte[]>();

        int sent = 0;
        int received = 0;

        var clientProcessor = new TestClientHandshakeProcessor
        (
            mtu: mtu,
            domain: domain,
            receiveFunc: (_) =>
            {
                received++;

                if (0 < packetsFromServer.Count)
                {
                    var packet = packetsFromServer[0];
                    packetsFromServer.RemoveAt(0);
                    return Task.FromResult(new ReadOnlyMemory<byte>(packet));
                }
                else
                {
                    return Task.FromResult(new ReadOnlyMemory<byte>());
                }
            },
            sendFunc: (buffer, _) =>
            {
                sent++;

                Assert.True(buffer.Length <= mtu, $"buffer.Length: {buffer.Length}, mtu: {mtu}");

                var packets = serverProcessor.ProcessPacket(buffer);
                foreach (var packet in packets)
                {
                    Assert.True(packet.Length <= mtu, $"packet.Length: {packet.Length}, mtu: {mtu}");
                    packetsFromServer.Add(packet);
                }

                return Task.CompletedTask;
            }
        )
        {
            Timeout = TimeSpan.FromSeconds(10)
        };

        await clientProcessor.RunAsync();

        Assert.Equal(EClientHandshakeState.DONE, clientProcessor.State);

        if (mtu == 0xFFFF)
        {
            Assert.Equal(2, sent);
            Assert.Equal(6, received);
        }

        Assert.Equal(serverProcessor.ServerApplicationKey, clientProcessor.ServerApplicationKey);
        Assert.Equal(serverProcessor.ServerApplicationIV, clientProcessor.ServerApplicationIV);
        Assert.Equal(serverProcessor.ClientApplicationKey, clientProcessor.ClientApplicationKey);
        Assert.Equal(serverProcessor.ClientApplicationIV, clientProcessor.ClientApplicationIV);
        Assert.Equal(serverProcessor.ServerRecordNumberKey, clientProcessor.ServerRecordNumberKey);
        Assert.Equal(serverProcessor.ClientRecordNumberKey, clientProcessor.ClientRecordNumberKey);
    }

    [Theory]
    [InlineData(0xFFFF)]
    [InlineData(1400)]
    [InlineData(1024)]
    [InlineData(512)]
    [InlineData(256)]
    [InlineData(128)]
    [InlineData(64)]
    public async Task Handshake_100Percent_Reversed_SingleRecordInPacket(int mtu)
    {
        var domain = "example.com";
        using var certificate = CertificateHelper.GenerateSelfSignedCertificate(domain);

        var serverProcessor = new ServerHandshakeProcessor(certificate, mtu);

        var packetsFromServer = new List<byte[]>();

        var clientProcessor = new TestClientHandshakeProcessor
        (
            mtu: mtu,
            domain: domain,
            receiveFunc: (_) =>
            {
                if (0 < packetsFromServer.Count)
                {
                    var packet = packetsFromServer[0];
                    packetsFromServer.RemoveAt(0);
                    return Task.FromResult(new ReadOnlyMemory<byte>(packet));
                }
                else
                {
                    return Task.FromResult(new ReadOnlyMemory<byte>());
                }
            },
            sendFunc: (buffer, _) =>
            {
                Assert.True(buffer.Length <= mtu, $"buffer.Length: {buffer.Length}, mtu: {mtu}");

                var packets = serverProcessor.ProcessPacket(buffer);
                foreach (var packet in packets.Reverse())
                {
                    Assert.True(packet.Length <= mtu, $"packet.Length: {packet.Length}, mtu: {mtu}");
                    packetsFromServer.Add(packet);
                }

                return Task.CompletedTask;
            }
        );

        await clientProcessor.RunAsync();

        Assert.Equal(EClientHandshakeState.DONE, clientProcessor.State);

        Assert.Equal(serverProcessor.ServerApplicationKey, clientProcessor.ServerApplicationKey);
        Assert.Equal(serverProcessor.ServerApplicationIV, clientProcessor.ServerApplicationIV);
        Assert.Equal(serverProcessor.ClientApplicationKey, clientProcessor.ClientApplicationKey);
        Assert.Equal(serverProcessor.ClientApplicationIV, clientProcessor.ClientApplicationIV);
        Assert.Equal(serverProcessor.ServerRecordNumberKey, clientProcessor.ServerRecordNumberKey);
        Assert.Equal(serverProcessor.ClientRecordNumberKey, clientProcessor.ClientRecordNumberKey);
    }

    [Theory]
    [InlineData(0xFFFF)]
    [InlineData(1400)]
    [InlineData(1024)]
    [InlineData(512)]
    [InlineData(256)]
    [InlineData(128)]
    [InlineData(64)]
    public async Task Handshake_75Percent_Unordered_Timeouts_SingleRecordInPacket(int mtu)
    {
        var domain = "example.com";
        using var certificate = CertificateHelper.GenerateSelfSignedCertificate(domain);

        var serverProcessor = new ServerHandshakeProcessor(certificate, mtu);

        var packetsFromServer = new List<byte[]>();

        int dropped = 0;

        var clientProcessor = new TestClientHandshakeProcessor
        (
            mtu: mtu,
            domain: domain,
            receiveFunc: async (_) =>
            {
                if (0 < packetsFromServer.Count)
                {
                    var packet = packetsFromServer[0];
                    packetsFromServer.RemoveAt(0);

                    if (0.75 < Random.Shared.NextDouble())
                    {
                        dropped++;
                        return new ReadOnlyMemory<byte>();
                    }
                    else
                    {
                        if (0.75 < Random.Shared.NextDouble())
                            await Task.Delay(50);

                        return new ReadOnlyMemory<byte>(packet);
                    }
                }
                else
                {
                    return new ReadOnlyMemory<byte>();
                }
            },
            sendFunc: (buffer, _) =>
            {
                if (0.75 < Random.Shared.NextDouble())
                {
                    dropped++;
                    return Task.CompletedTask;
                }

                Assert.True(buffer.Length <= mtu, $"buffer.Length: {buffer.Length}, mtu: {mtu}");

                var packets = serverProcessor.ProcessPacket(buffer);
                foreach (var packet in packets.OrderBy(x => Random.Shared.NextDouble()))
                {
                    Assert.True(packet.Length <= mtu, $"packet.Length: {packet.Length}, mtu: {mtu}");
                    packetsFromServer.Add(packet);
                }

                return Task.CompletedTask;
            }
        )
        {
            Timeout = TimeSpan.FromMinutes(10),
            ResendInterval = TimeSpan.FromMilliseconds(25)
        };

        await clientProcessor.RunAsync();

        _output.WriteLine("Dropped: " + dropped);

        Assert.Equal(EClientHandshakeState.DONE, clientProcessor.State);

        Assert.Equal(serverProcessor.ServerApplicationKey, clientProcessor.ServerApplicationKey);
        Assert.Equal(serverProcessor.ServerApplicationIV, clientProcessor.ServerApplicationIV);
        Assert.Equal(serverProcessor.ClientApplicationKey, clientProcessor.ClientApplicationKey);
        Assert.Equal(serverProcessor.ClientApplicationIV, clientProcessor.ClientApplicationIV);
        Assert.Equal(serverProcessor.ServerRecordNumberKey, clientProcessor.ServerRecordNumberKey);
        Assert.Equal(serverProcessor.ClientRecordNumberKey, clientProcessor.ClientRecordNumberKey);
    }

    private class TestClientHandshakeProcessor : ClientHandshakeProcessor
    {
        private int _mtu;
        private string _domain;
        private Func<CancellationToken, Task<ReadOnlyMemory<byte>>> _receiveFunc;
        private Func<ReadOnlyMemory<byte>, CancellationToken, Task> _sendFunc;

        public TestClientHandshakeProcessor
        (
            int mtu,
            string domain,
            Func<CancellationToken, Task<ReadOnlyMemory<byte>>> receiveFunc,
            Func<ReadOnlyMemory<byte>, CancellationToken, Task> sendFunc
        )
        {
            _mtu = mtu;
            _domain = domain;
            _receiveFunc = receiveFunc;
            _sendFunc = sendFunc;
        }

        protected override int PacketMtu()
            => _mtu;

        protected override string RendezvousServerDomain()
            => _domain;

        protected override Task<ReadOnlyMemory<byte>> ReceiveAsync(CancellationToken ct)
            => _receiveFunc(ct);

        protected override Task SendAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
            => _sendFunc(buffer, ct);

        protected override bool ValidateCertificates(X509Certificate2[] certificates, string domain)
            => domain == _domain;
    }
}
