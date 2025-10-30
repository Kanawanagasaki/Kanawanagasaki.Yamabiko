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

    private ulong _clientLastRecordNumber = 0;
    private ulong _serverRecordCounter = 1;

    private HashSet<Guid> _subscribedProjects = [];

    private readonly Settings _settings;
    private readonly ITransport _transport;
    private readonly ClientsService _clientsService;
    private readonly ProjectsService _projectsService;

    public Client(IPEndPoint endPoint, Settings settings, ITransport transport, ClientsService clientsService, ProjectsService projectsService)
    {
        EndPoint = endPoint;
        _settings = settings;
        _transport = transport;
        _clientsService = clientsService;
        _projectsService = projectsService;
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
                _handshakeProcessor = new ServerHandshakeProcessor(_settings.Certificate, _settings.MTU);

            try
            {
                foreach (var resultBuffer in _handshakeProcessor.ProcessPacket(buffer))
                    await _transport.SendAsync(EndPoint, resultBuffer, ct);
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
                    var record = PlainTextRecord.Parse(buffer.Span, 0, 0, ref offset);
                    if (record.Type is ERecordType.ALERT)
                    {
                        var alert = Alert.Parse(record.Buffer);
                        if (alert.Type is EAlertType.CLOSE_NOTIFY)
                            _clientsService.RemoveClient(EndPoint);
                    }
                }
            }
            else
            {
                while (offset < buffer.Length)
                {
                    var record = CipherTextRecord.DecryptAndParse(buffer.Span, _clientAes, _clientAesIV, _clientHeaderAes, 0, _clientLastRecordNumber, ref offset);
                    if (_clientLastRecordNumber < record.RecordNumber)
                        _clientLastRecordNumber = record.RecordNumber;
                    if (record.Type is ERecordType.ALERT)
                    {
                        var alert = Alert.Parse(record.Buffer.Span);
                        if (alert.Type is EAlertType.CLOSE_NOTIFY)
                            _clientsService.RemoveClient(EndPoint);
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
        var packet = Packet.Parse(record.Buffer.Span);
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
                await ProcessQueryAsync(query, ct);
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
                await SendAckAsync(record, ct);
                break;
        }
    }

    private Task ProcessPingAsync(PingPacket ping, CancellationToken ct)
        => SendPacketsAsync([new PongPacket()], ct);

    private async Task ProcessAdvertiseAsync(AdvertisePacket ad, CipherTextRecord record, CancellationToken ct)
    {
        var peer = _projectsService.ProcessAdvertisement(this, ad);
        await SendAckAsync(record, ct);

        var project = _projectsService.GetProject(ad.ProjectId);
        if (project is not null)
        {
            foreach (var subscriber in project.GetSubscribers())
                await subscriber.SendPacketsAsync([peer.ToPacket(Guid.Empty, -1, project.Count)], ct);
        }
    }

    private async Task ProcessAdvertiseExtraAsync(AdvertiseExtraPacket adExtra, CipherTextRecord record, CancellationToken ct)
    {
        _projectsService.ProcessAdvertisementExtra(PeerId, adExtra);
        await SendAckAsync(record, ct);

        var project = _projectsService.GetProject(adExtra.ProjectId);
        if (project is not null)
        {
            var peerExtra = new PeerExtraPacket
            {
                RequestId = Guid.Empty,
                PeerId = PeerId,
                Tag = adExtra.Tag,
                Data = adExtra.Data,
            };
            foreach (var subscriber in project.GetSubscribers())
                await subscriber.SendPacketsAsync([peerExtra], ct);
        }
    }

    private async Task ProcessStopAdvertisingAsync(StopAdvertisingPacket stopAd, CipherTextRecord record, CancellationToken ct)
    {
        _projectsService.RemovePeer(PeerId);
        await SendAckAsync(record, ct);
    }

    private async Task ProcessSubscribeAsync(SubscribePacket subscribe, CipherTextRecord record, CancellationToken ct)
    {
        if (_subscribedProjects.Count < 8)
        {
            _subscribedProjects.Add(subscribe.ProjectId);
            _projectsService.ProcessSubscribe(this, subscribe);
        }

        await SendAckAsync(record, ct);
    }

    private async Task ProcessUnsubscribeAsync(UnsubscribePacket unsubscribe, CipherTextRecord record, CancellationToken ct)
    {
        _subscribedProjects.Remove(unsubscribe.ProjectId);
        _projectsService.ProcessUnsubscribe(PeerId, unsubscribe);
        await SendAckAsync(record, ct);
    }

    private async Task ProcessQueryAsync(QueryPacket query, CancellationToken ct)
    {
        var project = _projectsService.GetProject(query.ProjectId);
        if (project is null)
        {
            var emptyRes = new EmptyQueryResultPacket
            {
                RequestId = query.RequestId,
                Total = 0
            };
            await SendPacketsAsync([emptyRes], ct);
            return;
        }

        var (total, res) = project.Query(query);
        var packets = res.Select((x, i) => x.ToPacket(query.RequestId, i, total)).ToArray();
        if (packets.Length == 0)
        {
            var emptyRes = new EmptyQueryResultPacket
            {
                RequestId = query.RequestId,
                Total = 0
            };
            await SendPacketsAsync([emptyRes], ct);
        }
        else
        {
            await SendPacketsAsync(packets, ct);
        }
    }

    private async Task ProcessQueryExtraAsync(QueryExtraPacket queryExtra, CipherTextRecord record, CancellationToken ct)
    {
        if (queryExtra.TagsIds.Length == 0)
        {
            var emptyRes = new EmptyQueryExtraResultPacket
            {
                RequestId = queryExtra.RequestId,
                PeerId = PeerId,
                TagsIds = queryExtra.TagsIds
            };
            await SendPacketsAsync([emptyRes], ct);
            return;
        }

        var peer = _projectsService.GetPeer(queryExtra.PeerId);
        if (peer is null)
        {
            var emptyRes = new EmptyQueryExtraResultPacket
            {
                RequestId = queryExtra.RequestId,
                PeerId = PeerId,
                TagsIds = queryExtra.TagsIds
            };
            return;
        }

        var extras = new List<PeerExtraPacket>();
        foreach (var tag in queryExtra.TagsIds)
        {
            extras.Add(new PeerExtraPacket
            {
                RequestId = queryExtra.RequestId,
                PeerId = PeerId,
                Tag = tag,
                Data = peer.GetExtra(tag)
            });
        }

        await SendPacketsAsync(extras.ToArray(), ct);
    }

    private async Task ProcessConnectAsync(ConnectPacket connect, CancellationToken ct)
    {
        var peer = _projectsService.GetPeer(connect.PeerId);
        if (peer is null)
        {
            var connectDeny = new ConnectDenyPacket
            {
                ConnectionId = connect.ConnectionId,
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
                ConnectionId = connect.ConnectionId,
                PeerId = connect.PeerId,
                Reason = "Incorrect password"
            };
            await SendPacketsAsync([connectDeny], ct);
            return;
        }

        var peerConnect = new PeerConnectPacket
        {
            ConnectionId = connect.ConnectionId,
            PeerId = PeerId,
            PublicKey = connect.PublicKey,
            Ip = EndPoint.Address,
            Port = (ushort)EndPoint.Port
        };
        await peer.Client.SendPacketsAsync([peerConnect], ct);
    }

    private async Task ProcessConnectDenyAsync(ConnectDenyPacket connectDeny, CancellationToken ct)
    {
        var peer = _projectsService.GetPeer(connectDeny.PeerId);
        if (peer is null)
            return;

        var connectDeny2 = new ConnectDenyPacket
        {
            ConnectionId = connectDeny.ConnectionId,
            PeerId = PeerId,
            Reason = connectDeny.Reason
        };
        await peer.Client.SendPacketsAsync([connectDeny2], ct);
    }

    private async Task ProcessDirectConnectAsync(DirectConnectPacket directConnect, CancellationToken ct)
    {
        var client = _clientsService.GetClientByEndpoint(directConnect.Ip, directConnect.Port);
        if (client is null)
            return;

        var peerConnect = new PeerConnectPacket
        {
            ConnectionId = directConnect.ConnectionId,
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
                Epoch = 3,
                RecordNumber = _serverRecordCounter++
            };
            var buffer = new byte[record.Length()];
            record.EncryptAndWrite(buffer, _serverAes, _serverAesIV, _serverHeaderAes);
            await _transport.SendAsync(EndPoint, buffer, ct);
        }
        else
        {
            using var ms = new MemoryStream();

            foreach (var packet in packets)
            {
                var record = new CipherTextRecord(packet.ToByteArray())
                {
                    Type = ERecordType.APPLICATION_DATA,
                    Epoch = 3,
                    RecordNumber = _serverRecordCounter++
                };
                var buffer = new byte[record.Length()];
                record.EncryptAndWrite(buffer, _serverAes, _serverAesIV, _serverHeaderAes);

                if (_settings.MTU < ms.Length + buffer.Length)
                {
                    await _transport.SendAsync(EndPoint, ms.ToArray(), ct);
                    ms.SetLength(0);
                }

                ms.Write(buffer);
            }

            if (0 < ms.Length)
                await _transport.SendAsync(EndPoint, ms.ToArray(), ct);
        }
    }

    public async Task SendAckAsync(CipherTextRecord recordToAck, CancellationToken ct)
    {
        if (_serverAes is null || _serverAesIV is null || _serverHeaderAes is null)
            return;

        var ack = new Ack(recordToAck.Epoch, recordToAck.RecordNumber);
        var ackBuffer = new byte[ack.Length()];
        ack.Write(ackBuffer);

        var record = new CipherTextRecord(ackBuffer)
        {
            Type = ERecordType.ALERT,
            Epoch = 3,
            RecordNumber = _serverRecordCounter++
        };
        var buffer = new byte[record.Length()];
        record.EncryptAndWrite(buffer, _serverAes, _serverAesIV, _serverHeaderAes);
        await _transport.SendAsync(EndPoint, buffer, ct);
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
                Epoch = 3,
                RecordNumber = _serverRecordCounter++
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
                Epoch = 0,
                RecordNumber = 0
            };
            buffer = new byte[record.Length()];
            record.Write(buffer);
        }

        await _transport.SendAsync(EndPoint, buffer, ct);
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
