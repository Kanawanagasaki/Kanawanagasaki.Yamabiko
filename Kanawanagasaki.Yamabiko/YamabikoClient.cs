namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Exceptions;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using Kanawanagasaki.Yamabiko.Tags;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using System.Threading.Tasks;

public class YamabikoClient : IAsyncDisposable, IDisposable
{
    public delegate Task<PeerConnectResult> AcceptPeerDelegate(PeerConnectPacket peerConnect, CancellationToken ct);

    public delegate bool ValidateCertificatesDelegate(X509Certificate2[] certificates);
    public ValidateCertificatesDelegate? ValidateCertificatesCallback { get; init; }

    public delegate void PeerAdvertisementDelegate(PeerPacket peerPacket);
    public event PeerAdvertisementDelegate? OnPeerAdvertisement;

    public delegate void PeerExtraAdvertisementDelegate(PeerExtraPacket peerExtraPacket);
    public event PeerExtraAdvertisementDelegate? OnPeerExtraAdvertisement;

    public Guid ProjectId { get; }
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(90);
    public TimeSpan PingInterval { get; set; } = TimeSpan.FromSeconds(3);
    public TimeSpan ResendInterval { get; set; } = TimeSpan.FromSeconds(1);
    public string? CertificateDomain { get; set; }
    public YamabikoKcpOptions KcpOptions { get; }

    public EConnectionState ConnectionState { get; private set; } = EConnectionState.DISCONNECTED;

    public IPEndPoint ServerEndPoint { get; }

    private readonly YamabikoTransport _transport;

    private readonly ILoggerFactory? _loggerFactory;
    private readonly ILogger<YamabikoClient>? _logger;

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
    private ConcurrentDictionary<uint, YamabikoPeer> _peers = [];

    private Channel<(PeerConnectPacket peerConnect, long timestamp)>? _peersToAccept;

    public YamabikoClient(IPEndPoint serverEndpoint, Guid projectId, YamabikoTransport transport) : this(serverEndpoint, projectId, null, transport, null) { }

    public YamabikoClient(IPEndPoint serverEndpoint, Guid projectId, YamabikoKcpOptions? kcpOptions = null, YamabikoTransport? transport = null, ILoggerFactory? loggerFactory = null)
    {
        ServerEndPoint = serverEndpoint;
        ProjectId = projectId;
        KcpOptions = kcpOptions ?? new();

        _transport = transport ?? new UdpYamabikoTransport(KcpOptions.ReliableRecvWindowSize + KcpOptions.StreamRecvWindowSize);
        _loggerFactory = loggerFactory;
        _logger = loggerFactory?.CreateLogger<YamabikoClient>();
    }

    public async Task StartAsync(CancellationToken ct = default)
    {
        Stop();

        ConnectionState = EConnectionState.HANDSHAKE;

        try
        {
            _handshakeCts = new CancellationTokenSource();
            using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(_handshakeCts.Token, ct);

            _peersToAccept = Channel.CreateBounded<(PeerConnectPacket peerConnect, long timestamp)>(new BoundedChannelOptions(16)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });

            _handshakeProcessor = new YamabikoClientHandshakeProcessor(this, _transport, ValidateCertificatesCallback)
            {
                Timeout = Timeout
            };

            if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
                _logger.LogInformation("Starting handshake with rendezvous server (endpoint={endpoint}, projectId={projectId})", ServerEndPoint, ProjectId);

            await _handshakeProcessor.RunAsync(linkedCts.Token);

            _handshakeCts?.Dispose();
            _handshakeCts = null;
        }
        catch (Exception e)
        {
            ConnectionState = EConnectionState.DISCONNECTED;

            if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                _logger.LogError(e, "Handshake with rendezvous server failed (endpoint={endpoint})", ServerEndPoint);

            throw;
        }

        if (_handshakeProcessor.State is EClientHandshakeState.DONE
            && _handshakeProcessor.ClientApplicationKey is not null
            && _handshakeProcessor.ClientApplicationIV is not null
            && _handshakeProcessor.ClientRecordNumberKey is not null
            && _handshakeProcessor.ServerApplicationKey is not null
            && _handshakeProcessor.ServerApplicationIV is not null
            && _handshakeProcessor.ServerRecordNumberKey is not null)
        {
            if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
                _logger.LogInformation("Handshake complete - connected to rendezvous server (endpoint={endpoint}, projectId={projectId})", ServerEndPoint, ProjectId);

            ConnectionState = EConnectionState.CONNECTED;

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
        else
        {
            ConnectionState = EConnectionState.DISCONNECTED;
            if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                _logger.LogError("Handshake failed (state={state}, endpoint={endpoint})", _handshakeProcessor.State, ServerEndPoint);
            throw new DisconnectedException("Handshake with server failed");
        }
    }

    private async Task PingLoopAsync()
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Ping loop started (interval={interval}ms, endpoint={endpoint})", PingInterval.TotalMilliseconds, ServerEndPoint);

        while (_pingCts is not null && !_pingCts.IsCancellationRequested && ConnectionState is not EConnectionState.DISCONNECTED)
        {
            try
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Sending ping to rendezvous server (endpoint={endpoint})", ServerEndPoint);
                await SendPacketsAsync([new PingPacket()], false, _pingCts.Token);
                await Task.Delay(PingInterval, _pingCts.Token);
            }
            catch (OperationCanceledException)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Ping loop operation cancelled");
            }
            catch (Exception e)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                    _logger.LogError(e, "Unhandled exception in ping loop");
                break;
            }

            if (Timeout < Stopwatch.GetElapsedTime(_serverLastActivity))
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                    _logger.LogError("Server timed out (endpoint={endpoint}, elapsed={elapsed}ms)", ServerEndPoint, Stopwatch.GetElapsedTime(_serverLastActivity).TotalMilliseconds);
                await StopAsync(_pingCts.Token);
                ConnectionState = EConnectionState.DISCONNECTED;
                throw new DisconnectedException("Server timeout");
            }
        }

        ConnectionState = EConnectionState.DISCONNECTED;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Ping loop stopped (endpoint={endpoint})", ServerEndPoint);
    }

    private async Task ReceiveLoopAsync()
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Receive loop started (endpoint={endpoint})", ServerEndPoint);

        while (_receiveCts is not null && !_receiveCts.IsCancellationRequested && ConnectionState is not EConnectionState.DISCONNECTED)
        {
            try
            {
                var buffer = await _transport.ReceiveFromEndpointAsync(ServerEndPoint, _receiveCts.Token);
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received bytes (count={count}, endpoint={endpoint})", buffer.Length, ServerEndPoint);
                await ProcessBufferAsync(buffer, _receiveCts.Token);
            }
            catch (OperationCanceledException)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Receive loop operation cancelled");
            }
            catch (Exception e)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                    _logger.LogError(e, "Unhandled exception in receive loop");
                break;
            }
        }

        ConnectionState = EConnectionState.DISCONNECTED;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Receive loop stopped (endpoint={endpoint})", ServerEndPoint);
    }

    private async Task ProcessBufferAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (buffer.Length < 1)
            return;
        if (_serverAes is null || _serverIV is null || _serverRecordNumberAes is null)
            return;

        int offset = 0;

        while (offset < buffer.Length)
        {
            if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("Processing encrypted record from server (offset={offset}, total={total})", offset, buffer.Length);

            var record = CipherTextRecord.DecryptAndParse(buffer.Span, _serverAes, _serverIV, _serverRecordNumberAes, 0, _serverLastRecordNumber, ref offset);

            if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("Processing record (type={type}, recordNumber={recordNumber})", record.Type, record.RecordNumber);

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

                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Received alert (type={type})", alert.Type);

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

                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received ack for record (recordNumber={recordNumber})", ack.RecordNumber);

                if (_acknowledgeableRecords.TryRemove(ack.RecordNumber, out var ackRecord))
                {
                    ackRecord.Acknowledge(ack);
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Record acknowledged (recordNumber={recordNumber})", ack.RecordNumber);
                }
                else
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("There were no record to acknowledge (recordNumber={recordNumber})", ack.RecordNumber);
                }
            }

            if (1024 < _acknowledgeableRecords.Count)
            {
                foreach (var recNum in _acknowledgeableRecords.Keys.Order().Take(_acknowledgeableRecords.Count / 2))
                {
                    if (_acknowledgeableRecords.TryRemove(recNum, out var ackRecord))
                    {
                        ackRecord.Discard();

                        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                            _logger.LogTrace("Record discarded (recordNumber={recordNumber})", recNum);
                    }
                }
            }
        }

        _serverLastActivity = Stopwatch.GetTimestamp();
    }

    private async Task ProcessRecordAsync(CipherTextRecord record, CancellationToken ct)
    {
        var packet = Packet.Parse(record.Buffer.Span);
        switch (packet)
        {
            case PongPacket pong:
                {
                    _serverLastActivity = Stopwatch.GetTimestamp();
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Pong packet");
                    break;
                }
            case EmptyQueryResultPacket emptyQueryResult:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Empty Query Result Packet (requestId={requestId})", emptyQueryResult.RequestId);
                    if (_queries.TryGetValue(emptyQueryResult.RequestId, out var queryResult))
                        queryResult.ProcessEmptyQueryPacket(emptyQueryResult);
                    break;
                }
            case EmptyQueryExtraResultPacket emptyQueryExtraResult:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Empty Query Extra Result Packet (requestId={requestId})", emptyQueryExtraResult.RequestId);
                    if (_queries.TryGetValue(emptyQueryExtraResult.RequestId, out var queryResult))
                        queryResult.ProcessEmptyQueryExtraPacket(emptyQueryExtraResult);
                    break;
                }
            case PeerPacket peer:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Peer Packet (requestId={requestId})", peer.RequestId);
                    if (_queries.TryGetValue(peer.RequestId, out var queryResult))
                        queryResult.ProcessPeerPacket(peer);
                    else if (peer.RequestId == Guid.Empty)
                        OnPeerAdvertisement?.Invoke(peer);
                    break;
                }
            case PeerExtraPacket peerExtra:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Peer Extra Packet (requestId={requestId})", peerExtra.RequestId);
                    if (_queries.TryGetValue(peerExtra.RequestId, out var queryResult))
                        queryResult.ProcessPeerExtraPacket(peerExtra);
                    else if (peerExtra.RequestId == Guid.Empty)
                        OnPeerExtraAdvertisement?.Invoke(peerExtra);
                    break;
                }
            case ConnectDenyPacket connectDeny:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Connect Deny Packet (connectionId={connectionId}) with reason: {reason}", connectDeny.ConnectionId, connectDeny.Reason);
                    if (_peers.TryGetValue(connectDeny.ConnectionId, out var peer))
                        await peer.ProcessConnectDenyAsync(connectDeny, ct);
                    break;
                }
            case PeerConnectPacket peerConnect:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Peer Connect Packet (connectionId={connectionId})", peerConnect.ConnectionId);
                    if (_peersToAccept is not null)
                        await _peersToAccept.Writer.WriteAsync((peerConnect, Stopwatch.GetTimestamp()), ct);
                    break;
                }
            case DirectConnectPacket directConnect:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                        _logger.LogTrace("Received Direct Connect Packet (connectionId={connectionId})", directConnect.ConnectionId);
                    if (_peers.TryGetValue(directConnect.ConnectionId, out var peer))
                    {
                        peer.ProcessDirectConnect(directConnect);
                        await peer.PingAsync(ct);
                    }
                    break;
                }
            default:
                {
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                        _logger.LogDebug("Received unsupported packet type (type={type}, recordNumber={recordNumber})", packet.Type, record.RecordNumber);
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
                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Attempting DirectConnect to peer (endpoint={endpoint})", peer.RemoteEndpoint);
                await SendPacketsAsync([new DirectConnectPacket
                {
                    ConnectionId = peer.ConnectionId,
                    PublicKey = peer.PublicKey,
                    Ip = peer.RemoteEndpoint.Address,
                    Port = (ushort)peer.RemoteEndpoint.Port,
                    LanIp = _transport.GetLanIp(),
                    LanPort = _transport.GetLanPort()
                }], false, linkedCts.Token);
            }
            await Task.Delay(ResendInterval, linkedCts.Token);
        }
        while (peer.ConnectionState is EConnectionState.CONNECTING);
    }

    public async Task AdvertiseAsync(Advertisement ad, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Advertising '{name}' (flags={flags}, projectId={projectId})", ad.Name, ad.Flags, ProjectId);

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

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Advertising tags (count={count}, projectId={projectId})", tags.Count(), ProjectId);

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

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Clearing tags (count={count}, projectId={projectId})", tagIds.Count(), ProjectId);

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

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Stopping advertising (projectId={projectId})", ProjectId);

        await SendPacketsAsync([new StopAdvertisingPacket()], true, ct);
    }

    public async Task SubscribeAsync(CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Subscribing (projectId={projectId})", ProjectId);

        await SendPacketsAsync([new SubscribePacket { ProjectId = ProjectId }], true, ct);
    }

    public async Task UnsubscribeAsync(CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Unsubscribing (projectId={projectId})", ProjectId);

        await SendPacketsAsync([new UnsubscribePacket { ProjectId = ProjectId }], true, ct);
    }

    public async Task<QueryResult> QueryAsync(Query query, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Starting query (projectId={projectId})", ProjectId);

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
                    if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                        _logger.LogDebug("Resending missing query packets (requestId={requestId})", queryRes.RequestId);

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
            if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Query completed (requestId={requestId}, projectId={projectId})", queryRes.RequestId, ProjectId);
        }

        return queryRes;
    }

    public async Task<YamabikoPeer> ConnectAsync(PeerInfo queryPeer, string? password = null, byte[]? extra = null, CancellationToken ct = default)
    {
        if (_clientAes is null || _clientIV is null || _clientRecordNumberAes is null)
            throw new DisconnectedException("Not connected to rendezvous server");

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Starting connection to peer (peerId={peerId})", queryPeer.PeerId);

        var peer = new YamabikoPeer(_transport, queryPeer.PeerId, KcpOptions, _loggerFactory)
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
                    PeerId = peer.RemotePeerId,
                    Password = password,
                    PublicKey = peer.PublicKey,
                    Extra = extra,
                    LanIp = _transport.GetLanIp(),
                    LanPort = _transport.GetLanPort()
                }], false, linkedCts.Token);
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Sent Connect packet (connectionId={connectionId}, peerId={peerId})", peer.ConnectionId, peer.RemotePeerId);
                await Task.Delay(ResendInterval, linkedCts.Token);
            }
            while (peer.ConnectionState is EConnectionState.HANDSHAKE);
        }
        catch (OperationCanceledException)
        {
            if (peer.ConnectionState is EConnectionState.HANDSHAKE or EConnectionState.CONNECTING)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning("Connect attempt to peer timed out/cancelled (peerId={peerId})", queryPeer.PeerId);
                await peer.DisconnectAsync(ct);
            }
        }

        if (peer.ConnectionState is EConnectionState.DISCONNECTED)
        {
            if (peer.DenyReason is not null)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
                    _logger.LogInformation("Connection to peer denied (peerId={peerId}, reason={reason})", queryPeer.PeerId, peer.DenyReason);
                throw new ConnectionDeniedException("Connection denied with reason: " + peer.DenyReason);
            }
            else
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning("Connection to peer timed out (peerId={peerId})", queryPeer.PeerId);
                throw new TimeoutException("Connection timed out");
            }
        }

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Connection to peer established (peerId={peerId}, connectionId={connectionId})", queryPeer.PeerId, peer.ConnectionId);
        return peer;
    }

    private async Task SendPacketsAsync(Packet[] packets, bool shouldWaitAck, CancellationToken ct)
    {
        if (packets.Length == 0)
            return;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Sending packets (count={count}, waitAck={wait})", packets.Length, shouldWaitAck);

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
                        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                            _logger.LogTrace("Resending {count} ack-waiting records", ackRecords.Count);
                        await SendRecordsAsync(ackRecords.Values.Select(x => x.Record).ToArray(), ct);
                    }
                    else
                    {
                        var ack = await await whenAnyAckTask;
                        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                            _logger.LogTrace("Received acknowledgement for record (recordNumber={recordNumber})", ack.RecordNumber);
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
                {
                    if (_acknowledgeableRecords.TryRemove(ackNum, out var ackRec))
                    {
                        ackRec.Discard();
                        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                            _logger.LogTrace("Discarded pending ack record (recordNumber={recordNumber})", ackNum);
                    }
                }
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
        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Sending alert (alert={alert}, endpoint={endpoint})", alertType, ServerEndPoint);

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

    internal async Task SendBufferAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Sending bytes (len={len}, endpoint={endpoint})", buffer.Length, endpoint);

        await _transport.SendAsync(endpoint, buffer, ct);
    }

    public Task<YamabikoPeer?> AcceptPeerAsync(CancellationToken ct = default)
        => AcceptPeerAsync((_, _) => Task.FromResult(PeerConnectResult.Accept()), ct);

    public async Task<YamabikoPeer?> AcceptPeerAsync(AcceptPeerDelegate acceptPeerCallback, CancellationToken ct = default)
    {
        if (_peersToAccept is null)
            return null;

        while (!ct.IsCancellationRequested)
        {
            var (peerConnect, timestamp) = await _peersToAccept.Reader.ReadAsync(ct);

            if (Timeout < Stopwatch.GetElapsedTime(timestamp))
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Ignored expired peer connection request (peerId={peerId})", peerConnect.PeerId);
                continue;
            }

            var acceptResult = await acceptPeerCallback(peerConnect, ct);

            if (!acceptResult.IsAccepted)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
                    _logger.LogInformation("Rejecting connection from peer (peerId={peerId}, connectionId={connectionId}, reason={reason})", peerConnect.PeerId, peerConnect.ConnectionId, acceptResult.Reason);
                var connectDeny = new ConnectDenyPacket
                {
                    ConnectionId = peerConnect.ConnectionId,
                    PeerId = peerConnect.PeerId,
                    Reason = acceptResult.Reason
                };
                await SendPacketsAsync([connectDeny], false, ct);
                continue;
            }

            var peer = _peers.AddOrUpdate
            (
                peerConnect.ConnectionId,
                connectionId =>
                {
                    var peer = new YamabikoPeer(_transport, connectionId, peerConnect.PeerId, KcpOptions, _loggerFactory)
                    {
                        Timeout = Timeout,
                        ResendInterval = ResendInterval,
                        PingInterval = PingInterval
                    };
                    peer.ProcessPeerConnect(peerConnect);
                    Task.Run(() => DirectConnectAsync(peer, ct));
                    return peer;
                },
                (_, peer) =>
                {
                    peer.ProcessPeerConnect(peerConnect);
                    return peer;
                }
            );
            await peer.PingAsync(ct);

            if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
                _logger.LogInformation("Accepted and initialized peer (peerId={peerId}, connectionId={connectionId})", peerConnect.PeerId, peerConnect.ConnectionId);
            return peer;
        }

        return null;
    }

    public async Task StopAsync(CancellationToken ct = default)
    {
        await SendAlertAsync(EAlertType.CLOSE_NOTIFY, ct);
        Stop();
    }

    private void Stop()
    {
        if (ConnectionState is not EConnectionState.DISCONNECTED && _logger is not null && _logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Stopping YamabikoClient (endpoint={endpoint})", ServerEndPoint);

        ConnectionState = EConnectionState.DISCONNECTED;

        _peersToAccept?.Writer.TryComplete();
        _peersToAccept = null;

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

    public void Dispose()
    {
        Stop();
        _transport.Dispose();

        _receiveTask?.Dispose();
        _pingTask?.Dispose();
    }
}
