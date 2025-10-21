namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Handshake;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using System;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;

public class Client : IDisposable
{
    public Guid PeerId { get; } = Guid.CreateVersion7();

    public IPEndPoint EndPoint { get; }

    public long LastActivity { get; private set; } = 0;

    private ServerHandshakeProcessor? _handshakeProcessor;

    private AesGcm? _clientAes;
    private byte[]? _clientAesIV;
    private Aes? _clientHeaderAes;

    private AesGcm? _serverAes;
    private byte[]? _serverAesIV;
    private Aes? _serverHeaderAes;

    private ulong _recordCounter = 1;

    private HashSet<Guid> _subscribedProjects = [];

    public Client(IPEndPoint endPoint)
    {
        EndPoint = endPoint;
    }

    public async Task ProcessBufferAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (buffer.Length < 1)
            return;

        var isHandshakePacket = false;

        if ((buffer.Span[0] & (byte)EHeaderFlags.FIXED_BITS) != CipherTextRecord.HEADER_BITS && buffer.Span[0] == (byte)ERecordType.HANDSHAKE)
            isHandshakePacket = true;
        else if ((buffer.Span[0] & (byte)EHeaderFlags.ENCRYPTION_EPOCH) == 2)
            isHandshakePacket = true;

        if (isHandshakePacket)
        {
            if (_handshakeProcessor is null)
                _handshakeProcessor = new ServerHandshakeProcessor(Settings.Certificate, Settings.MTU);

            try
            {
                foreach (var resultBuffer in _handshakeProcessor.ProcessPacket(buffer))
                    await UdpService.SendPacketAsync(EndPoint, resultBuffer, ct);
            }
            catch
            {
                await SendAlertBufferAsync(EAlertType.INTERNAL_ERROR, ct);
            }

            if (_handshakeProcessor.ServerApplicationKey is not null
                && _handshakeProcessor.ServerApplicationIV is not null
                && _handshakeProcessor.ServerRecordNumberKey is not null
                && _handshakeProcessor.ClientApplicationKey is not null
                && _handshakeProcessor.ClientApplicationIV is not null
                && _handshakeProcessor.ClientRecordNumberKey is not null)
            {
                _serverAes?.Dispose();
                _serverHeaderAes?.Dispose();

                _serverAes = new AesGcm(_handshakeProcessor.ServerApplicationKey, AesGcm.TagByteSizes.MaxSize);

                _serverAesIV = _handshakeProcessor.ServerApplicationIV;

                _serverHeaderAes = Aes.Create();
                _serverHeaderAes.KeySize = 128;
                _serverHeaderAes.Key = _handshakeProcessor.ServerRecordNumberKey;
                _serverHeaderAes.Mode = CipherMode.ECB;
                _serverHeaderAes.Padding = PaddingMode.None;

                _clientAes?.Dispose();
                _clientHeaderAes?.Dispose();

                _clientAes = new AesGcm(_handshakeProcessor.ClientApplicationKey, AesGcm.TagByteSizes.MaxSize);

                _clientAesIV = _handshakeProcessor.ClientApplicationIV;

                _clientHeaderAes = Aes.Create();
                _clientHeaderAes.KeySize = 128;
                _clientHeaderAes.Key = _handshakeProcessor.ClientRecordNumberKey;
                _clientHeaderAes.Mode = CipherMode.ECB;
                _clientHeaderAes.Padding = PaddingMode.None;
            }
        }
        else
        {
            int offset = 0;

            if (_clientAes is null || _clientAesIV is null || _clientHeaderAes is null)
            {
                while (offset < buffer.Length)
                {
                    var record = PlainTextRecord.Parse(buffer.Span, ref offset);
                    if (record.Type is ERecordType.ALERT)
                    {
                        var alert = Alert.Parse(record.Buffer);
                        if (alert.Type is EAlertType.CLOSE_NOTIFY)
                            ClientsService.RemoveClient(EndPoint);
                    }
                }
            }
            else
            {
                while (offset < buffer.Length)
                {
                    var record = CipherTextRecord.DecryptAndParse(buffer.Span, _clientAes, _clientAesIV, _clientHeaderAes, ref offset);
                    if (record.Type is ERecordType.ALERT)
                    {
                        var alert = Alert.Parse(record.Buffer);
                        if (alert.Type is EAlertType.CLOSE_NOTIFY)
                            ClientsService.RemoveClient(EndPoint);
                    }
                    else
                    {
                        try
                        {
                            await ProcessRecordAsync(record, ct);
                        }
                        catch
                        {
                            await SendAlertBufferAsync(EAlertType.INTERNAL_ERROR, ct);
                        }
                    }
                }
            }
        }

        LastActivity = Stopwatch.GetTimestamp();
    }

    private async Task ProcessRecordAsync(CipherTextRecord record, CancellationToken ct)
    {
        var packet = Packet.Parse(record.Buffer);
        switch (packet)
        {
            case PingPacket ping:
                await ProcessPingAsync(ping, ct);
                break;
            case AdvertisePacket ad:
                await ProcessAdvertiseAsync(ad, record, ct);
                break;
            case AdvertiseExtraPacket adExtra:
                await ProcessAdvertiseExtraAsync(adExtra, record, ct);
                break;
            case StopAdvertisingPacket stopAd:
                await ProcessStopAdvertisingAsync(stopAd, record, ct);
                break;
            case SubscribePacket subscribe:
                await ProcessSubscribeAsync(subscribe, record, ct);
                break;
            case UnsubscribePacket unsubscribe:
                await ProcessUnsubscribeAsync(unsubscribe, record, ct);
                break;
            case QueryPacket query:
                await ProcessQueryAsync(query, record, ct);
                break;
            case QueryExtraPacket queryExtra:
                await ProcessQueryExtraAsync(queryExtra, record, ct);
                break;
            case ConnectPacket connect:
                await ProcessConnectAsync(connect, ct);
                break;
            case ConnectDenyPacket connectDeny:
                await ProcessConnectDenyAsync(connectDeny, ct);
                break;
            case DirectConnectPacket directConnect:
                await ProcessDirectConnectAsync(directConnect, ct);
                break;
            default:
                await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
                break;
        }
    }

    private Task ProcessPingAsync(PingPacket ping, CancellationToken ct)
        => SendPacketsAsync([new PongPacket()], ct);

    private async Task ProcessAdvertiseAsync(AdvertisePacket ad, CipherTextRecord record, CancellationToken ct)
    {
        var peer = ProjectsService.ProcessAdvertisement(this, ad);
        await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);

        var project = ProjectsService.GetProject(ad.ProjectId);
        if (project is not null)
        {
            foreach (var subscriber in project.GetSubscribers())
                await subscriber.SendPacketsAsync([peer.ToPacket(-1)], ct);
        }
    }

    private async Task ProcessAdvertiseExtraAsync(AdvertiseExtraPacket adExtra, CipherTextRecord record, CancellationToken ct)
    {
        ProjectsService.ProcessAdvertisementExtra(PeerId, adExtra);
        await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
    }

    private async Task ProcessStopAdvertisingAsync(StopAdvertisingPacket stopAd, CipherTextRecord record, CancellationToken ct)
    {
        ProjectsService.RemovePeer(PeerId);
        await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
    }

    private async Task ProcessSubscribeAsync(SubscribePacket subscribe, CipherTextRecord record, CancellationToken ct)
    {
        if (_subscribedProjects.Count < 8)
        {
            _subscribedProjects.Add(subscribe.ProjectId);
            ProjectsService.ProcessSubscribe(this, subscribe);
        }

        await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
    }

    private async Task ProcessUnsubscribeAsync(UnsubscribePacket unsubscribe, CipherTextRecord record, CancellationToken ct)
    {
        _subscribedProjects.Remove(unsubscribe.ProjectId);
        ProjectsService.ProcessUnsubscribe(PeerId, unsubscribe);
        await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
    }

    private async Task ProcessQueryAsync(QueryPacket query, CipherTextRecord record, CancellationToken ct)
    {
        var project = ProjectsService.GetProject(query.ProjectId);
        if (project is null)
        {
            await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
            return;
        }

        var packets = project.Query(query)
                             .Select((x, i) => x.ToPacket(i))
                             .ToArray();
        if (packets.Length == 0)
            await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
        else
            await SendPacketsAsync(packets, ct);
    }

    private async Task ProcessQueryExtraAsync(QueryExtraPacket queryExtra, CipherTextRecord record, CancellationToken ct)
    {
        if (queryExtra.ExtraTags.Length == 0)
        {
            await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
            return;
        }

        var peer = ProjectsService.GetPeer(queryExtra.PeerId);
        if (peer is null)
        {
            await SendAckAsync(record.EpochLowBits, record.RecordNumber, ct);
            return;
        }

        var extras = new List<PeerExtraPacket>();
        foreach (var tag in queryExtra.ExtraTags)
        {
            extras.Add(new PeerExtraPacket
            {
                PeerId = PeerId,
                Tag = tag,
                Data = peer.GetExtra(tag)
            });
        }

        await SendPacketsAsync(extras.ToArray(), ct);
    }

    private async Task ProcessConnectAsync(ConnectPacket connect, CancellationToken ct)
    {
        var peer = ProjectsService.GetPeer(connect.PeerId);
        if (peer is null)
        {
            var connectDeny = new ConnectDenyPacket
            {
                PeerId = connect.PeerId,
                Reason = "Peer not found"
            };
            await SendPacketsAsync([connectDeny], ct);
            return;
        }

        if (peer.Password is not null && peer.Password != connect.Password)
        {
            var connectDeny = new ConnectDenyPacket
            {
                PeerId = connect.PeerId,
                Reason = "Incorrect password"
            };
            await SendPacketsAsync([connectDeny], ct);
            return;
        }

        var peerConnect = new PeerConnectPacket
        {
            PeerId = PeerId,
            PublicKey = connect.PublicKey,
            Ip = EndPoint.Address,
            Port = (ushort)EndPoint.Port
        };
        await peer.Client.SendPacketsAsync([peerConnect], ct);
    }

    private async Task ProcessConnectDenyAsync(ConnectDenyPacket connectDeny, CancellationToken ct)
    {
        var peer = ProjectsService.GetPeer(connectDeny.PeerId);
        if (peer is null)
            return;

        var connectDeny2 = new ConnectDenyPacket
        {
            PeerId = PeerId,
            Reason = connectDeny.Reason
        };
        await peer.Client.SendPacketsAsync([connectDeny2], ct);
    }

    private async Task ProcessDirectConnectAsync(DirectConnectPacket directConnect, CancellationToken ct)
    {
        var client = ClientsService.GetClientByEndpoint(directConnect.Ip, directConnect.Port);
        if (client is null)
            return;

        var peerConnect = new PeerConnectPacket
        {
            PeerId = PeerId,
            PublicKey = directConnect.PublicKey,
            Ip = EndPoint.Address,
            Port = (ushort)EndPoint.Port
        };
        await client.SendPacketsAsync([peerConnect], ct);
    }

    public async Task SendPacketsAsync(Packet[] packets, CancellationToken ct)
    {
        if (_serverAes is null || _serverAesIV is null || _serverHeaderAes is null)
            return;

        if (packets.Length == 0)
            return;
        else if (packets.Length == 1)
        {
            var record = new CipherTextRecord(packets[0].ToByteArray())
            {
                Type = ERecordType.APPLICATION_DATA,
                EpochLowBits = 3,
                RecordNumber = (ushort)(_recordCounter++)
            };
            var buffer = new byte[record.Length()];
            record.EncryptAndWrite(buffer, _serverAes, _serverAesIV, _serverHeaderAes);
            await UdpService.SendPacketAsync(EndPoint, buffer, ct);
        }
        else
        {
            using var ms = new MemoryStream();

            foreach (var packet in packets)
            {
                var record = new CipherTextRecord(packet.ToByteArray())
                {
                    Type = ERecordType.APPLICATION_DATA,
                    EpochLowBits = 3,
                    RecordNumber = (ushort)(_recordCounter++)
                };
                var buffer = new byte[record.Length()];
                record.EncryptAndWrite(buffer, _serverAes, _serverAesIV, _serverHeaderAes);

                if (Settings.MTU < ms.Length + buffer.Length)
                {
                    await UdpService.SendPacketAsync(EndPoint, ms.ToArray(), ct);
                    ms.SetLength(0);
                }

                ms.Write(buffer);
            }

            if (0 < ms.Length)
                await UdpService.SendPacketAsync(EndPoint, ms.ToArray(), ct);
        }
    }

    public async Task SendAckAsync(ulong epoch, ulong recordNumber, CancellationToken ct)
    {
        if (_serverAes is null || _serverAesIV is null || _serverHeaderAes is null)
            return;

        var ack = new Ack(epoch, recordNumber);
        var ackBuffer = new byte[ack.Length()];
        ack.Write(ackBuffer);

        var record = new CipherTextRecord(ackBuffer)
        {
            Type = ERecordType.ALERT,
            EpochLowBits = 3,
            RecordNumber = (ushort)(_recordCounter++)
        };
        var buffer = new byte[record.Length()];
        record.EncryptAndWrite(buffer, _serverAes, _serverAesIV, _serverHeaderAes);
        await UdpService.SendPacketAsync(EndPoint, buffer, ct);
    }

    public async Task SendAlertBufferAsync(EAlertType alertType, CancellationToken ct)
    {
        byte[] buffer;

        if (_serverAes is not null && _serverAesIV is not null && _serverHeaderAes is not null)
        {
            var alert = new Alert(alertType);
            var alertBuffer = new byte[alert.Length()];
            alert.Write(alertBuffer);

            var record = new CipherTextRecord(alertBuffer)
            {
                Type = ERecordType.ALERT,
                EpochLowBits = 3,
                RecordNumber = (ushort)(_recordCounter++)
            };
            buffer = new byte[record.Length()];
            record.EncryptAndWrite(buffer, _serverAes, _serverAesIV, _serverHeaderAes);
        }
        else if (_handshakeProcessor is not null)
        {
            buffer = _handshakeProcessor.GetAlertCipherText(alertType) ?? _handshakeProcessor.GetAlertPlainText(alertType);
        }
        else
        {
            var alert = new Alert(alertType);
            var alertBuffer = new byte[alert.Length()];
            alert.Write(alertBuffer);

            var record = new PlainTextRecord(alertBuffer)
            {
                Type = ERecordType.ALERT,
                KeyEpoch = 0,
                RecordNumber = 0
            };
            buffer = new byte[record.Length()];
            record.Write(buffer);
        }

        await UdpService.SendPacketAsync(EndPoint, buffer, ct);
    }

    public void Dispose()
    {
        _clientAes?.Dispose();
        _clientAes = null;

        _clientHeaderAes?.Dispose();
        _clientHeaderAes = null;

        _serverAes?.Dispose();
        _serverAes = null;

        _serverHeaderAes?.Dispose();
        _serverHeaderAes = null;
    }
}
