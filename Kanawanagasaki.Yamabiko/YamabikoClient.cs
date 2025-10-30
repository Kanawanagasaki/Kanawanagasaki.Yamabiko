namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Exceptions;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using Kanawanagasaki.Yamabiko.Tags;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

public class YamabikoClient : IAsyncDisposable
{
    public delegate Task<PeerConnectResult> AcceptPeerDelegate(PeerConnectPacket peerConnect, CancellationToken ct);
    public required AcceptPeerDelegate AcceptPeerCallback { get; init; }

    public event Action<YamabikoPeer>? OnPeerConnection;

    public Guid ProjectId { get; }
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(90);
    public TimeSpan PingInterval { get; set; } = TimeSpan.FromSeconds(3);
    public TimeSpan ResendInterval { get; set; } = TimeSpan.FromSeconds(1);
    public string? CertificateDomain { get; set; }

    public IPEndPoint ServerEndPoint { get; }

    private readonly YamabikoTransport _transport;

    private YamabikoClientHandshakeProcessor? _handshakeProcessor;
    private CancellationTokenSource? _handshakeCts;

    private AesGcm? _clientAes;
    private byte[]? _clientIV;
    private Aes? _clientRecordNumberAes;

    private AesGcm? _serverAes;
    private byte[]? _serverIV;
    private Aes? _serverRecordNumberAes;

    private CancellationTokenSource? _pingCts;
    private Task? _pingTask;
    private CancellationTokenSource? _receiveCts;
    private Task? _receiveTask;

    private ulong _serverLastRecordNumber = 1;
    private ulong _clientRecordCounter = 0;
    private long _serverLastActivity = 0;

    private ConcurrentDictionary<ulong, AcknowledgeableRecord> _acknowledgeableRecords = [];
    private ConcurrentDictionary<Guid, QueryResult> _queries = [];
    private ConcurrentDictionary<Guid, YamabikoPeer> _peers = [];

    public YamabikoClient(IPEndPoint serverEndpoint, Guid projectId)
    {
        ServerEndPoint = serverEndpoint;
        ProjectId = projectId;

        _transport = new UdpYamabikoTransport();
    }

    public YamabikoClient(IPEndPoint serverEndpoint, Guid projectId, YamabikoTransport transport)
    {
        ServerEndPoint = serverEndpoint;
        ProjectId = projectId;

        _transport = transport;
    }

    public async Task StartAsync(CancellationToken ct = default)
    {
        Stop();

        _handshakeCts = new CancellationTokenSource();
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(_handshakeCts.Token, ct);

        _handshakeProcessor = new YamabikoClientHandshakeProcessor(this)
        {
            Timeout = Timeout
        };
        await _handshakeProcessor.RunAsync(linkedCts.Token);

        _handshakeCts?.Dispose();
        _handshakeCts = null;

        if (_handshakeProcessor.State is EClientHandshakeState.DONE
            && _handshakeProcessor.ClientApplicationKey is not null
            && _handshakeProcessor.ClientApplicationIV is not null
            && _handshakeProcessor.ClientRecordNumberKey is not null
            && _handshakeProcessor.ServerApplicationKey is not null
            && _handshakeProcessor.ServerApplicationIV is not null
            && _handshakeProcessor.ServerRecordNumberKey is not null)
        {
            _clientAes = new AesGcm(_handshakeProcessor.ClientApplicationKey, AesGcm.TagByteSizes.MaxSize);
            _clientIV = _handshakeProcessor.ClientApplicationIV;
            _clientRecordNumberAes = Aes.Create();
            _clientRecordNumberAes.KeySize = 128;
            _clientRecordNumberAes.Key = _handshakeProcessor.ClientRecordNumberKey;
            _clientRecordNumberAes.Mode = CipherMode.ECB;
            _clientRecordNumberAes.Padding = PaddingMode.None;

            _serverAes = new AesGcm(_handshakeProcessor.ServerApplicationKey, AesGcm.TagByteSizes.MaxSize);
            _serverIV = _handshakeProcessor.ServerApplicationIV;
            _serverRecordNumberAes = Aes.Create();
            _serverRecordNumberAes.KeySize = 128;
            _serverRecordNumberAes.Key = _handshakeProcessor.ServerRecordNumberKey;
            _serverRecordNumberAes.Mode = CipherMode.ECB;
            _serverRecordNumberAes.Padding = PaddingMode.None;

            _handshakeProcessor.Dispose();
            _handshakeProcessor = null;

            _serverLastRecordNumber = 1;
            _clientRecordCounter = 0;
            _serverLastActivity = Stopwatch.GetTimestamp();

            _pingTask?.Dispose();
            _pingCts = new CancellationTokenSource();
            _pingTask = PingLoopAsync();

            _receiveTask?.Dispose();
            _receiveCts = new CancellationTokenSource();
            _receiveTask = ReceiveLoopAsync();
        }
    }

    private async Task PingLoopAsync()
    {
        while (_pingCts is not null && !_pingCts.IsCancellationRequested)
        {
            try
            {
                await SendPacketsAsync([new PingPacket()], false, _pingCts.Token);
                await Task.Delay(PingInterval, _pingCts.Token);
            }
            catch { }

            if (Timeout < Stopwatch.GetElapsedTime(_serverLastActivity))
            {
                Stop();
                throw new DisconnectedException("Server timeout");
            }
        }
    }

    private async Task ReceiveLoopAsync()
    {
        while (_receiveCts is not null && !_receiveCts.IsCancellationRequested)
        {
            try
            {
                var buffer = await _transport.ReceiveFromEndpointAsync(ServerEndPoint, _receiveCts.Token);
                await ProcessBufferAsync(buffer, _receiveCts.Token);
            }
            catch (OperationCanceledException) { }
        }
    }

    public async Task ProcessBufferAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (buffer.Length < 1)
            return;
        if (_serverAes is null || _serverIV is null || _serverRecordNumberAes is null)
            return;

        int offset = 0;

        while (offset < buffer.Length)
        {
            var record = CipherTextRecord.DecryptAndParse(buffer.Span, _serverAes, _serverIV, _serverRecordNumberAes, 0, _serverLastRecordNumber, ref offset);

            if (1024 <= _serverLastRecordNumber)
            {
                for (ulong recNum = _serverLastRecordNumber; recNum <= record.RecordNumber; recNum++)
                    if (_acknowledgeableRecords.TryRemove(recNum - 1024, out var ackRecord))
                        ackRecord.Discard();
            }

            if (_serverLastRecordNumber < record.RecordNumber)
                _serverLastRecordNumber = record.RecordNumber;

            if (record.Type is ERecordType.ALERT)
            {
                var alert = Alert.Parse(record.Buffer.Span);
                if (alert.Type is EAlertType.CLOSE_NOTIFY)
                {
                    Stop();
                    throw new DisconnectedException("Server close notify");
                }
            }
            else if (record.Type is ERecordType.APPLICATION_DATA)
            {
                await ProcessRecordAsync(record, ct);
            }
            else if (record.Type is ERecordType.ACK)
            {
                var ack = Ack.Parse(record.Buffer.Span);
                if (_acknowledgeableRecords.TryRemove(record.RecordNumber, out var ackRecord))
                    ackRecord.Acknowledge(ack);
            }

            if (1024 < _acknowledgeableRecords.Count)
            {
                foreach (var recNum in _acknowledgeableRecords.Keys.Order().Take(_acknowledgeableRecords.Count / 2))
                    if (_acknowledgeableRecords.TryRemove(recNum, out var ackRecord))
                        ackRecord.Discard();
            }
        }

        _serverLastActivity = Stopwatch.GetTimestamp();
    }

    private async Task ProcessRecordAsync(CipherTextRecord record, CancellationToken ct)
    {
        var packet = Packet.Parse(record.Buffer.Span);
        switch (packet)
        {
            case EmptyQueryResultPacket emptyQueryResult:
                {
                    if (_queries.TryGetValue(emptyQueryResult.RequestId, out var queryResult))
                        queryResult.ProcessEmptyQueryPacket(emptyQueryResult);
                    break;
                }
            case EmptyQueryExtraResultPacket emptyQueryExtraResult:
                {
                    if (_queries.TryGetValue(emptyQueryExtraResult.RequestId, out var queryResult))
                        queryResult.ProcessEmptyQueryExtraPacket(emptyQueryExtraResult);
                    break;
                }
            case PeerPacket peer:
                {
                    if (_queries.TryGetValue(peer.RequestId, out var queryResult))
                        queryResult.ProcessPeerPacket(peer);
                    break;
                }
            case PeerExtraPacket peerExtra:
                {
                    if (_queries.TryGetValue(peerExtra.RequestId, out var queryResult))
                        queryResult.ProcessPeerExtraPacket(peerExtra);
                    break;
                }
            case ConnectDenyPacket connectDeny:
                {
                    if (_peers.TryGetValue(connectDeny.ConnectionId, out var peer))
                        peer.ProcessConnectDeny(connectDeny);
                    break;
                }
            case PeerConnectPacket peerConnect:
                {
                    var acceptResult = await AcceptPeerCallback(peerConnect, ct);
                    if (acceptResult.IsAccepted)
                    {
                        var peer = _peers.AddOrUpdate
                        (
                            peerConnect.ConnectionId,
                            connectionId =>
                            {
                                var peer = new YamabikoPeer(_transport, connectionId, peerConnect.PeerId)
                                {
                                    Timeout = Timeout,
                                    ResendInterval = ResendInterval,
                                    PingInterval = PingInterval
                                };
                                peer.ProcessPeerConnect(peerConnect);
                                Task.Run(() => DirectConnectAsync(peer, ct));
                                OnPeerConnection?.Invoke(peer);
                                return peer;
                            },
                            (_, peer) =>
                            {
                                peer.ProcessPeerConnect(peerConnect);
                                return peer;
                            }
                        );
                        await peer.PingAsync(ct);
                    }
                    else
                    {
                        var connectDeny = new ConnectDenyPacket
                        {
                            ConnectionId = peerConnect.ConnectionId,
                            PeerId = peerConnect.PeerId,
                            Reason = acceptResult.Reason
                        };
                        await SendPacketsAsync([connectDeny], false, ct);
                    }
                    break;
                }
            case DirectConnectPacket directConnect:
                {
                    if (_peers.TryGetValue(directConnect.ConnectionId, out var peer))
                    {
                        peer.ProcessDirectConnect(directConnect);
                        await peer.PingAsync(ct);
                    }
                    break;
                }
        }
    }

    private async Task DirectConnectAsync(YamabikoPeer peer, CancellationToken ct)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(Timeout);
        do
        {
            if (peer.RemoteEndpoint is not null)
            {
                await SendPacketsAsync([new DirectConnectPacket
                {
                    ConnectionId = peer.ConnectionId,
                    PublicKey = peer.PublicKey,
                    Ip = peer.RemoteEndpoint.Address,
                    Port = (ushort)peer.RemoteEndpoint.Port
                }], false, linkedCts.Token);
            }
            await Task.Delay(ResendInterval, linkedCts.Token);
        }
        while (peer.ConnectionState is EPeerConnectionState.CONNECTING);
    }

    public async Task AdvertiseAsync(Advertisement ad, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        var packets = new List<Packet>
        {
            new AdvertisePacket
            {
                ProjectId = ProjectId,
                Name = ad.Name,
                Password = ad.Password,
                Flags = ad.Flags
            }
        };

        if (ad.Tags is not null)
        {
            foreach (var tag in ad.Tags)
                packets.Add(new AdvertiseExtraPacket
                {
                    ProjectId = ProjectId,
                    Tag = tag.TagId,
                    Data = tag.ToByteArray()
                });
        }

        await SendPacketsAsync(packets.ToArray(), true, ct);
    }

    public async Task AdvertiseTagsAsync(IEnumerable<ITag> tags, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        var packets = tags.Select(x => new AdvertiseExtraPacket
        {
            ProjectId = ProjectId,
            Tag = x.TagId,
            Data = x.ToByteArray()
        }).ToArray();
        await SendPacketsAsync(packets.ToArray(), true, ct);
    }

    public async Task ClearTagsAsync(IEnumerable<byte> tagIds, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        var packets = tagIds.Select(x => new AdvertiseExtraPacket
        {
            ProjectId = ProjectId,
            Tag = x,
            Data = null
        }).ToArray();
        await SendPacketsAsync(packets.ToArray(), true, ct);
    }

    public async Task StopAdvertisingAsync(CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        await SendPacketsAsync([new StopAdvertisingPacket()], true, ct);
    }

    public async Task Subscribe(CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        await SendPacketsAsync([new SubscribePacket { ProjectId = ProjectId }], true, ct);
    }

    public async Task Unsubscribe(CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        await SendPacketsAsync([new UnsubscribePacket { ProjectId = ProjectId }], true, ct);
    }

    public async Task<QueryResult> QueryAsync(Query query, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        var timeoutTask = Task.Delay(Timeout, ct);

        var queryPacket = query.ToPacket(ProjectId);
        var queryRes = new QueryResult(queryPacket);
        _queries.AddOrUpdate(queryRes.RequestId, queryRes, (_, _) => queryRes);

        await SendPacketsAsync([queryPacket], false, ct);

        try
        {
            while (!queryRes.IsCompleted())
            {
                ct.ThrowIfCancellationRequested();

                var nextPacketTask = queryRes.AwaitNextPacketAsync(ct);
                var resendDelay = Task.Delay(ResendInterval, ct);
                var first = await Task.WhenAny(timeoutTask, nextPacketTask, resendDelay);
                if (first == timeoutTask)
                    throw new TimeoutException("Query has been timed out");
                else if (first == resendDelay)
                {
                    var packets = new List<Packet>();

                    var missingIndices = queryRes.GetMissingIndices();
                    if (0 < missingIndices.Count)
                    {
                        var order = missingIndices.Order();
                        var start = order.First();
                        var end = start;
                        foreach (var index in order.Skip(1))
                        {
                            if (1 < index - end)
                            {
                                packets.Add(queryPacket.CopyWithRange((ushort)start, (byte)(end - start + 1)));
                                start = index;
                            }
                            end = index;
                        }
                        packets.Add(queryPacket.CopyWithRange((ushort)start, (byte)(end - start + 1)));
                    }

                    var missingTags = queryRes.GetMissingTags();
                    if (0 < missingTags.Count)
                    {
                        foreach (var (peerId, tagsIds) in missingTags)
                        {
                            packets.Add(new QueryExtraPacket
                            {
                                RequestId = queryRes.RequestId,
                                PeerId = peerId,
                                TagsIds = tagsIds.ToArray()
                            });
                        }
                    }

                    if (0 < packets.Count)
                        await SendPacketsAsync(packets.ToArray(), false, ct);
                }
                else if (await nextPacketTask is PeerPacket peerPacket)
                {
                    var missingTags = queryRes.GetMissingTags();
                    if (missingTags.TryGetValue(peerPacket.PeerId, out var tagsIds))
                    {
                        var queryExtraPacket = new QueryExtraPacket
                        {
                            RequestId = queryRes.RequestId,
                            PeerId = peerPacket.PeerId,
                            TagsIds = tagsIds.ToArray()
                        };
                        await SendPacketsAsync([queryExtraPacket], false, ct);
                    }
                }
            }
        }
        finally
        {
            _queries.TryRemove(queryRes.RequestId, out _);
        }

        return queryRes;
    }

    public async Task<YamabikoPeer> ConnectAsync(QueryPeerResult queryPeer, string? password = null, byte[]? extra = null, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        var peer = new YamabikoPeer(_transport, queryPeer.PeerId)
        {
            Timeout = Timeout,
            ResendInterval = ResendInterval,
            PingInterval = PingInterval
        };
        _peers.TryAdd(peer.ConnectionId, peer);

        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        linkedCts.CancelAfter(Timeout);
        try
        {
            do
            {
                await SendPacketsAsync([new ConnectPacket
                {
                    ConnectionId = peer.ConnectionId,
                    PeerId = peer.PeerId,
                    Password = password,
                    PublicKey = peer.PublicKey,
                    Extra = extra
                }], false, linkedCts.Token);
                await Task.Delay(ResendInterval, linkedCts.Token);
            }
            while (peer.ConnectionState is EPeerConnectionState.HANDSHAKE or EPeerConnectionState.CONNECTING);
        }
        catch (OperationCanceledException)
        {
            if (peer.ConnectionState is EPeerConnectionState.HANDSHAKE or EPeerConnectionState.CONNECTING)
                peer.Disconnect();
        }

        if (peer.ConnectionState is EPeerConnectionState.DISCONNECTED)
        {
            if (peer.DenyReason is not null)
                throw new ConnectionDeniedException("Connection denied with reason: " + peer.DenyReason);
            else
                throw new TimeoutException("Connection timed out");
        }

        return peer;
    }

    private async Task SendPacketsAsync(Packet[] packets, bool shouldWaitAck, CancellationToken ct)
    {
        if (packets.Length == 0)
            return;

        if (shouldWaitAck)
        {
            var ackRecords = packets.Select(x => new AcknowledgeableRecord(PreparePacket(x)))
                                    .ToDictionary(x => x.Record.RecordNumber);

            foreach (var ackRecord in ackRecords.Values)
                _acknowledgeableRecords.TryAdd(ackRecord.Record.RecordNumber, ackRecord);

            try
            {
                var ackTasks = ackRecords.Values.ToDictionary(x => x.Record.RecordNumber, x => x.WaitAcknowledgment(Timeout, ct));

                await SendRecordsAsync(ackRecords.Values.Select(x => x.Record).ToArray(), ct);

                while (0 < ackRecords.Count)
                {
                    ct.ThrowIfCancellationRequested();

                    var whenAnyAckTask = Task.WhenAny(ackTasks.Values);
                    var resendTimeout = Task.Delay(ResendInterval, ct);

                    var first = await Task.WhenAny(whenAnyAckTask, resendTimeout);

                    if (first == resendTimeout)
                    {
                        await SendRecordsAsync(ackRecords.Values.Select(x => x.Record).ToArray(), ct);
                    }
                    else
                    {
                        var ack = await await whenAnyAckTask;
                        if (ackRecords.ContainsKey(ack.RecordNumber))
                            ackRecords.Remove(ack.RecordNumber);
                        if (ackTasks.ContainsKey(ack.RecordNumber))
                            ackTasks.Remove(ack.RecordNumber);
                    }
                }
            }
            finally
            {
                foreach (var ackNum in ackRecords.Keys)
                    if (_acknowledgeableRecords.TryRemove(ackNum, out var ackRec))
                        ackRec.Discard();
            }
        }
        else
        {
            var records = packets.Select(PreparePacket).ToArray();
            await SendRecordsAsync(records, ct);
        }
    }

    private CipherTextRecord PreparePacket(Packet packet)
        => new CipherTextRecord(packet.ToByteArray())
        {
            Type = ERecordType.APPLICATION_DATA,
            Epoch = 3,
            RecordNumber = Interlocked.Increment(ref _clientRecordCounter)
        };

    private async Task SendRecordsAsync(CipherTextRecord[] records, CancellationToken ct)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            return;

        if (records.Length == 0)
            return;
        else if (records.Length == 1)
        {
            var buffer = new byte[records[0].Length()];
            records[0].EncryptAndWrite(buffer, _clientAes, _clientIV, _clientRecordNumberAes);
            await SendBufferAsync(ServerEndPoint, buffer, ct);
        }
        else
        {
            using var ms = new MemoryStream();

            foreach (var record in records)
            {
                var buffer = new byte[record.Length()];
                record.EncryptAndWrite(buffer, _clientAes, _clientIV, _clientRecordNumberAes);

                if (1400 < ms.Length + buffer.Length)
                {
                    await SendBufferAsync(ServerEndPoint, ms.ToArray(), ct);
                    ms.SetLength(0);
                }

                ms.Write(buffer);
            }

            if (0 < ms.Length)
                await SendBufferAsync(ServerEndPoint, ms.ToArray(), ct);
        }
    }

    private async Task SendAlertAsync(EAlertType alertType, CancellationToken ct)
    {
        byte[] buffer;

        if (_clientAes is not null && _clientIV is not null && _clientRecordNumberAes is not null)
        {
            var alert = new Alert(alertType);
            var alertBuffer = new byte[alert.Length()];
            alert.Write(alertBuffer);

            var record = new CipherTextRecord(alertBuffer)
            {
                Type = ERecordType.ALERT,
                Epoch = 3,
                RecordNumber = Interlocked.Increment(ref _clientRecordCounter)
            };
            buffer = new byte[record.Length()];
            record.EncryptAndWrite(buffer, _clientAes, _clientIV, _clientRecordNumberAes);
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

        await SendBufferAsync(ServerEndPoint, buffer, ct);
    }

    public async Task SendBufferAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
        => await _transport.SendAsync(endpoint, buffer, ct);

    public async Task StopAsync()
    {
        await SendAlertAsync(EAlertType.CLOSE_NOTIFY, default);
        Stop();
    }

    private void Stop()
    {
        _receiveCts?.Cancel();
        _receiveCts?.Dispose();
        _receiveCts = null;

        _pingCts?.Cancel();
        _pingCts?.Dispose();
        _pingCts = null;

        _clientAes?.Dispose();
        _clientAes = null;
        _clientIV = null;
        _clientRecordNumberAes?.Dispose();
        _clientRecordNumberAes = null;

        _serverAes?.Dispose();
        _serverAes = null;
        _serverIV = null;
        _serverRecordNumberAes?.Dispose();
        _serverRecordNumberAes = null;

        _handshakeCts?.Cancel();
        _handshakeCts?.Dispose();
        _handshakeCts = null;

        _handshakeProcessor?.Dispose();
        _handshakeProcessor = null;
    }

    public async ValueTask DisposeAsync()
    {
        Stop();
        await _transport.DisposeAsync();

        _receiveTask?.Dispose();
        _pingTask?.Dispose();
    }
}
