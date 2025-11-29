namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using Kanawanagasaki.Yamabiko.Exceptions;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using Microsoft.Extensions.Logging;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Channels;

public class YamabikoPeer : IAsyncDisposable, IDisposable
{
    public TimeSpan Timeout { get; set; } = TimeSpan.FromSeconds(90);
    public TimeSpan ResendInterval { get; set; } = TimeSpan.FromSeconds(1);
    public TimeSpan PingInterval { get; set; } = TimeSpan.FromSeconds(3);

    public uint ConnectionId { get; }
    private byte[]? _connectionId;

    public Guid RemotePeerId { get; }

    public IPEndPoint? RemoteEndpoint { get; private set; }
    public TimeSpan Ping { get; private set; } = TimeSpan.FromTicks(-1);
    private long _pingLastTime = -1;
    private long[] _pingReceiveTimestamps = new long[5];

    private readonly byte[] _privateKey;
    internal byte[] PublicKey { get; }

    private YamabikoTransport _transport;

    private AesGcm? _localAes;
    private byte[]? _localAesIV;
    private Aes? _localAesHeader;

    private AesGcm? _remoteAes;
    private byte[]? _remoteAesIV;
    private Aes? _remoteAesHeader;

    public EConnectionState ConnectionState { get; private set; } = EConnectionState.HANDSHAKE;
    public string? DenyReason { get; private set; }

    private readonly CancellationTokenSource _cts = new();
    private readonly TaskCompletionSource _connectedTcs = new();

    private ulong _lastPeerRecordNumber = 0;
    private ulong _recordNumberCounter = 0;
    private long _lastActivity = 0;

    private readonly Channel<ReadOnlyMemory<byte>> _unreliableChannel;
    private readonly ReliableTransport _reliableKcp;
    private readonly ReliableTransport _streamKcp;

    private readonly ILogger<YamabikoPeer>? _logger;

    private bool _disposed;

    public YamabikoPeer(YamabikoTransport transport, uint connectionId, Guid peerId, YamabikoKcpOptions options, ILoggerFactory? loggerFactory)
    {
        _transport = transport;
        ConnectionId = connectionId;
        RemotePeerId = peerId;

        _privateKey = RandomNumberGenerator.GetBytes(32);
        PublicKey = KeyHashHelper.GenerateX25519PublicKey(_privateKey);

        _logger = loggerFactory?.CreateLogger<YamabikoPeer>();

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Created YamabikoPeer (connectionId={connectionId}, peerId={peerId})", ConnectionId, RemotePeerId);

        _unreliableChannel = Channel.CreateBounded<ReadOnlyMemory<byte>>(new BoundedChannelOptions(128)
        {
            FullMode = BoundedChannelFullMode.DropOldest
        });

        _reliableKcp = new ReliableTransport(this, ConnectionId);
        _reliableKcp.OnLogMessage += ReliableKcp_OnLogMessage;
        _reliableKcp.SetNoDelay(options.ReliableNoDelay, options.ReliableIntervalMs, options.ReliableFastResend, options.ReliableNoCongestionControl);
        _reliableKcp.SetWindowSize(options.ReliableSendWindowSize, options.ReliableRecvWindowSize);
        _reliableKcp.SetMtu(options.ReliableMtu);
        _reliableKcp.Start();

        _streamKcp = new ReliableTransport(this, ConnectionId);
        _streamKcp.OnLogMessage += StreamKcp_OnLogMessage;
        _streamKcp.SetStreamMode(true);
        _streamKcp.SetNoDelay(options.StreamNoDelay, options.StreamIntervalMs, options.StreamFastResend, options.StreamNoCongestionControl);
        _streamKcp.SetWindowSize(options.StreamSendWindowSize, options.StreamRecvWindowSize);
        _streamKcp.SetMtu(options.StreamMtu);
        _streamKcp.Start();

        _lastActivity = Stopwatch.GetTimestamp();

        Task.Run(ReceiveLoopAsync);
        Task.Run(PingLoopAsync);
    }

    public YamabikoPeer(YamabikoTransport transport, Guid peerId, YamabikoKcpOptions options, ILoggerFactory? loggerFactory)
        : this(transport, BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)), peerId, options, loggerFactory) { }

    private void ReliableKcp_OnLogMessage(string obj)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("KCP reliable (message={message}, connectionId={connectionId})", obj, ConnectionId);
    }

    private void StreamKcp_OnLogMessage(string obj)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("KCP stream (message={message}, connectionId={connectionId})", obj, ConnectionId);
    }

    internal void ProcessPeerConnect(PeerConnectPacket peerConnect)
    {
        if (ConnectionState is not EConnectionState.HANDSHAKE)
            return;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Connecting to a remote peer (connectionId={connectionId}, peerId={peerId}, ip={ip}, port={port})", peerConnect.ConnectionId, peerConnect.PeerId, peerConnect.Ip, peerConnect.Port);

        ConnectionState = EConnectionState.CONNECTING;
        DeriveKeys(peerConnect.PublicKey);
        RemoteEndpoint = new IPEndPoint(peerConnect.Ip, peerConnect.Port);
    }

    internal void ProcessDirectConnect(DirectConnectPacket directConnect)
    {
        if (ConnectionState is not EConnectionState.HANDSHAKE)
            return;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Connecting to a remote peer directly (connectionId={connectionId}, ip={ip}, port={port})", directConnect.ConnectionId, directConnect.Ip, directConnect.Port);

        ConnectionState = EConnectionState.CONNECTING;
        DeriveKeys(directConnect.PublicKey);
        RemoteEndpoint = new IPEndPoint(directConnect.Ip, directConnect.Port);
    }

    private void DeriveKeys(byte[] remotePublicKey)
    {
        var iAmPeer1 = KeyHashHelper.CompareByteArrayLex(PublicKey, remotePublicKey) < 0;

        var shared = KeyHashHelper.SharedSecret(_privateKey, remotePublicKey);
        var handshakeSecret = KeyHashHelper.HKDF_Extract(KeyHashHelper.EARLY_DERIVED, shared);

        var transcriptInput = iAmPeer1 ? PublicKey.Concat(remotePublicKey).ToArray() : remotePublicKey.Concat(PublicKey).ToArray();
        var transcriptHash = SHA256.HashData(transcriptInput);

        var derived = KeyHashHelper.HKDF_ExpandLabel(handshakeSecret, "derived", null, 32, KeyHashHelper.DTLS_PREFIX);
        var masterSecret = KeyHashHelper.HKDF_Extract(null, derived);

        var peer1AppTraffic = KeyHashHelper.DeriveSecret(masterSecret, "c ap traffic", transcriptHash, KeyHashHelper.DTLS_PREFIX);
        var peer2AppTraffic = KeyHashHelper.DeriveSecret(masterSecret, "s ap traffic", transcriptHash, KeyHashHelper.DTLS_PREFIX);

        var peer1Key = KeyHashHelper.HKDF_ExpandLabel(peer1AppTraffic, "key", null, 16, KeyHashHelper.DTLS_PREFIX);
        var peer1IV = KeyHashHelper.HKDF_ExpandLabel(peer1AppTraffic, "iv", null, AesGcm.NonceByteSizes.MaxSize, KeyHashHelper.DTLS_PREFIX);
        var peer1HeaderKey = KeyHashHelper.HKDF_ExpandLabel(peer1AppTraffic, "sn", null, 16, KeyHashHelper.DTLS_PREFIX);

        var peer2Key = KeyHashHelper.HKDF_ExpandLabel(peer2AppTraffic, "key", null, 16, KeyHashHelper.DTLS_PREFIX);
        var peer2IV = KeyHashHelper.HKDF_ExpandLabel(peer2AppTraffic, "iv", null, AesGcm.NonceByteSizes.MaxSize, KeyHashHelper.DTLS_PREFIX);
        var peer2HeaderKey = KeyHashHelper.HKDF_ExpandLabel(peer2AppTraffic, "sn", null, 16, KeyHashHelper.DTLS_PREFIX);

        _localAes?.Dispose();
        _localAesHeader?.Dispose();
        _remoteAes?.Dispose();
        _remoteAesHeader?.Dispose();

        _localAes = new AesGcm(iAmPeer1 ? peer1Key : peer2Key, AesGcm.TagByteSizes.MaxSize);
        _localAesIV = iAmPeer1 ? peer1IV : peer2IV;
        _localAesHeader = Aes.Create();
        _localAesHeader.KeySize = 128;
        _localAesHeader.Key = iAmPeer1 ? peer1HeaderKey : peer2HeaderKey;
        _localAesHeader.Mode = CipherMode.ECB;
        _localAesHeader.Padding = PaddingMode.None;

        _remoteAes = new AesGcm(iAmPeer1 ? peer2Key : peer1Key, AesGcm.TagByteSizes.MaxSize);
        _remoteAesIV = iAmPeer1 ? peer2IV : peer1IV;
        _remoteAesHeader = Aes.Create();
        _remoteAesHeader.KeySize = 128;
        _remoteAesHeader.Key = iAmPeer1 ? peer2HeaderKey : peer1HeaderKey;
        _remoteAesHeader.Mode = CipherMode.ECB;
        _remoteAesHeader.Padding = PaddingMode.None;
    }

    internal async Task ProcessConnectDenyAsync(ConnectDenyPacket connectDeny, CancellationToken ct)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Connection to peer denied (connectionId={connectionId}, reason={reason})", connectDeny.ConnectionId, connectDeny.Reason);

        DenyReason = connectDeny.Reason;
        await InternalDisconnectAsync(false, ct);
    }

    private async Task ReceiveLoopAsync()
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Receive loop started (connectionId={connectionId})", ConnectionId);

        while (!_cts.IsCancellationRequested && ConnectionState is not EConnectionState.DISCONNECTED)
        {
            try
            {
                var receiveResult = await _transport.ReceiveFromConnectionIdAsync(ConnectionId, _cts.Token);
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received from transport (connectionId={connectionId}, bytes={bytes}, remote={remote})", ConnectionId, receiveResult.Buffer.Length, receiveResult.RemoteEndPoint);
                await ProcessBufferAsync(receiveResult, _cts.Token);
            }
            catch (OperationCanceledException)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Receive loop operation cancelled (connectionId={connectionId})", ConnectionId);
            }
            catch (Exception e)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                    _logger.LogError(e, "Unhandled exception in ReceiveLoop (connectionId={connectionId})", ConnectionId);
            }
        }

        ConnectionState = EConnectionState.DISCONNECTED;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Receive loop stopped (connectionId={connectionId})", ConnectionId);
    }

    private async Task ProcessBufferAsync(YamabikoReceiveResult receiveResult, CancellationToken ct)
    {
        if (ConnectionState is EConnectionState.DISCONNECTED)
            return;

        if (_remoteAes is null || _remoteAesIV is null || _remoteAesHeader is null)
            return;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Processing buffer (connectionId={connectionId}, length={length})", ConnectionId, receiveResult.Buffer.Length);

        int offset = 0;
        var record = CipherTextRecord.DecryptAndParse(receiveResult.Buffer.Span, _remoteAes, _remoteAesIV, _remoteAesHeader, 0, _lastPeerRecordNumber, 4, ref offset);
        if (_lastPeerRecordNumber < record.RecordNumber)
            _lastPeerRecordNumber = record.RecordNumber;

        _lastActivity = Stopwatch.GetTimestamp();

        if (ConnectionState is EConnectionState.CONNECTING)
        {
            ConnectionState = EConnectionState.CONNECTED;
            RemoteEndpoint = receiveResult.RemoteEndPoint;
            _connectedTcs.TrySetResult();

            if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
                _logger.LogInformation("Remote peer connected (connectionId={connectionId}, peerId={peerId}, remote={remote})", ConnectionId, RemotePeerId, RemoteEndpoint);
        }

        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Processed record (type={type}, recordNumber={recordNumber})", record.Type, record.RecordNumber);

        switch (record.Type)
        {
            case ERecordType.ALERT:
                var alert = Alert.Parse(record.Buffer.Span);
                await ProcessAlertAsync(alert, ct);
                break;
            case ERecordType.APPLICATION_DATA:
                await ProcessRecordAsync(record, ct);
                break;
        }
    }

    private async Task ProcessAlertAsync(Alert alert, CancellationToken ct)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Processing alert (connectionId={connectionId}, type={type})", ConnectionId, alert.Type);

        if (alert.Type is EAlertType.CLOSE_NOTIFY)
            await InternalDisconnectAsync(ConnectionState is EConnectionState.CONNECTING or EConnectionState.CONNECTED, ct);
    }

    private async Task ProcessRecordAsync(CipherTextRecord record, CancellationToken ct)
    {
        if (record.Buffer.Length == 0)
            return;

        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Processing peer record (connectionId={connectionId}, length={length})", ConnectionId, record.Buffer.Length);

        switch ((EPeerPacketType)record.Buffer.Span[0])
        {
            case EPeerPacketType.PING:
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received PING (connectionId={connectionId})", ConnectionId);
                await ProcessPingAsync(record.Buffer[1..], ct);
                break;
            case EPeerPacketType.PONG:
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received PONG (connectionId={connectionId})", ConnectionId);
                ProcessPong();
                break;
            case EPeerPacketType.UNRELIABLE:
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received UNRELIABLE (connectionId={connectionId}, bytes={bytes})", ConnectionId, record.Buffer.Length - 1);
                await _unreliableChannel.Writer.WriteAsync(record.Buffer[1..], ct);
                break;
            case EPeerPacketType.RELIABLE:
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received RELIABLE (connectionId={connectionId}, bytes={bytes})", ConnectionId, record.Buffer.Length - 1);
                _reliableKcp.Input(record.Buffer[1..]);
                break;
            case EPeerPacketType.STREAM:
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received STREAM (connectionId={connectionId}, bytes={bytes})", ConnectionId, record.Buffer.Length - 1);
                _streamKcp.Input(record.Buffer[1..]);
                if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                    _logger.LogTrace("Received STREAM, input complete (connectionId={connectionId}, bytes={bytes})", ConnectionId, record.Buffer.Length - 1);
                break;
            default:
                if (_logger is not null && _logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning("Unknown peer packet type (connectionId={connectionId}, type={type})", ConnectionId, record.Buffer.Span[0]);
                break;
        }
    }

    private async Task ProcessPingAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (_pingReceiveTimestamps[^1] != 0 && Stopwatch.GetElapsedTime(_pingReceiveTimestamps[^1]) < TimeSpan.FromSeconds(1))
            return;

        _pingReceiveTimestamps[4] = _pingReceiveTimestamps[3];
        _pingReceiveTimestamps[3] = _pingReceiveTimestamps[2];
        _pingReceiveTimestamps[2] = _pingReceiveTimestamps[1];
        _pingReceiveTimestamps[1] = _pingReceiveTimestamps[0];
        _pingReceiveTimestamps[0] = Stopwatch.GetTimestamp();

        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Replying with PONG (connectionId={connectionId})", ConnectionId);

        await EncryptAndSendBufferAsync(EPeerPacketType.PONG, buffer, ct);
    }

    private void ProcessPong()
    {
        if (0 < _pingLastTime)
        {
            Ping = Stopwatch.GetElapsedTime(_pingLastTime);
            _pingLastTime = -1;
            if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("Last activity update (connectionId={connectionId}, pingMs={ping})", ConnectionId, Ping.TotalMilliseconds);
        }
    }

    private async Task PingLoopAsync()
    {
        using var timer = new PeriodicTimer(PingInterval);

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Ping loop started (connectionId={connectionId}, intervalMs={interval})", ConnectionId, PingInterval.TotalMilliseconds);

        try
        {
            do
            {
                await PingAsync(_cts.Token);

                _reliableKcp.Flush();
                _streamKcp.Flush();
            }
            while (!_cts.IsCancellationRequested
                    && ConnectionState is not EConnectionState.DISCONNECTED
                    && Stopwatch.GetElapsedTime(_lastActivity) < Timeout
                    && await timer.WaitForNextTickAsync(_cts.Token));
        }
        catch (OperationCanceledException)
        {
            if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("Ping loop operation cancelled (connectionId={connectionId})", ConnectionId);
        }
        catch (Exception e)
        {
            if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                _logger.LogError(e, "Unhandled exception in PingLoop (connectionId={connectionId})", ConnectionId);
        }

        await InternalDisconnectAsync(true, default);

        if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
            _logger.LogDebug("Ping loop stopped (connectionId={connectionId})", ConnectionId);
    }

    internal async Task PingAsync(CancellationToken ct = default)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Sending PING (connectionId={connectionId})", ConnectionId);

        _pingLastTime = Stopwatch.GetTimestamp();
        await EncryptAndSendBufferAsync(EPeerPacketType.PING, Array.Empty<byte>(), ct);
    }

    public Task SendUnreliableAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Sending unreliable (connectionId={connectionId}, len={len})", ConnectionId, buffer.Length);
        return EncryptAndSendBufferAsync(EPeerPacketType.UNRELIABLE, buffer, ct);
    }

    public async Task<ReadOnlyMemory<byte>> ReceiveUnreliableAsync(CancellationToken ct = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
        var buffer = await _unreliableChannel.Reader.ReadAsync(linkedCts.Token);

        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Received unreliable (connectionId={connectionId}, len={len})", ConnectionId, buffer.Length);

        return buffer;
    }

    public void SendReliable(ReadOnlyMemory<byte> buffer)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Sending reliable (connectionId={connectionId}, len={len})", ConnectionId, buffer.Length);
        _reliableKcp.Write(buffer);
    }

    public async ValueTask<ReadOnlyMemory<byte>> ReceiveReliableAsync(CancellationToken ct = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct, _cts.Token);
        var buffer = await _reliableKcp.ReadAsync(linkedCts.Token);

        if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
            _logger.LogTrace("Received reliable (connectionId={connectionId}, len={len})", ConnectionId, buffer.Length);

        return buffer;
    }

    public Stream GetStream()
        => _streamKcp.GetStream();

    internal async Task EncryptAndSendBufferAsync(EPeerPacketType packetType, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (RemoteEndpoint is null)
            return;
        if (_localAes is null || _localAesIV is null || _localAesHeader is null)
            return;

        var rentedBuffer = ArrayPool<byte>.Shared.Rent(1 + buffer.Length);
        try
        {
            if (_connectionId is null)
            {
                _connectionId = new byte[4];
                int offset = 0;
                BinaryHelper.Write(ConnectionId, _connectionId, ref offset);
            }

            var bufferWithType = rentedBuffer.AsMemory(0, 1 + buffer.Length);
            bufferWithType.Span[0] = (byte)packetType;
            buffer.CopyTo(bufferWithType[1..]);
            var record = new CipherTextRecord(bufferWithType)
            {
                Type = ERecordType.APPLICATION_DATA,
                Epoch = 3,
                RecordNumber = Interlocked.Increment(ref _recordNumberCounter),
                ConnectionId = _connectionId
            };

            if (_logger is not null && _logger.IsEnabled(LogLevel.Trace))
                _logger.LogTrace("Sending encrypted record (connectionId={connectionId}, packetType={packetType}, recordNumber={recordNumber}, len={len}, remote={remote})", ConnectionId, packetType, record.RecordNumber, buffer.Length, RemoteEndpoint);

            var recordLength = record.Length(true, false);
            var recordRentedBuffer = ArrayPool<byte>.Shared.Rent(recordLength);
            try
            {
                var recordBuffer = recordRentedBuffer.AsMemory(0, recordLength);
                record.EncryptAndWrite(recordBuffer.Span, _localAes, _localAesIV, _localAesHeader, true, false);
                await _transport.SendAsync(RemoteEndpoint, recordBuffer, ct);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(recordRentedBuffer);
            }
        }
        catch (Exception e)
        {
            if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                _logger.LogError(e, "Failed to encrypt and send buffer (connectionId={connectionId}, packetType={packetType})", ConnectionId, packetType);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedBuffer);
        }
    }

    public async Task WaitUntilConnectedAsync(TimeSpan timeout, CancellationToken ct = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        try
        {
            var timeoutTask = Task.Delay(timeout, linkedCts.Token);
            var first = await Task.WhenAny(timeoutTask, _connectedTcs.Task);
            if (first == timeoutTask)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning("WaitUntilConnected timed out (connectionId={connectionId})", ConnectionId);
                throw new TimeoutException("Connection has timed out");
            }
            if (ConnectionState is EConnectionState.DISCONNECTED)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Warning))
                    _logger.LogWarning("WaitUntilConnected detected disconnected state (connectionId={connectionId})", ConnectionId);
                throw new DisconnectedException("Peer disconnected");
            }

            if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                _logger.LogDebug("WaitUntilConnected success (connectionId={connectionId})", ConnectionId);
        }
        finally
        {
            linkedCts.Cancel();
        }
    }

    public Task DisconnectAsync(CancellationToken ct = default)
        => InternalDisconnectAsync(true, ct);

    private async Task InternalDisconnectAsync(bool shouldNotifyRemotePeer, CancellationToken ct)
    {
        if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Disconnecting (connectionId={connectionId})", ConnectionId);

        ConnectionState = EConnectionState.DISCONNECTED;

        _cts.Cancel();
        _connectedTcs.TrySetResult();

        if (shouldNotifyRemotePeer && RemoteEndpoint is not null && _localAes is not null && _localAesIV is not null && _localAesHeader is not null)
        {
            try
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Sending close_notify alert to remote (connectionId={connectionId}, remote={remote})", ConnectionId, RemoteEndpoint);

                var alert = new Alert(EAlertType.CLOSE_NOTIFY);
                var alertBuffer = new byte[alert.Length()];
                alert.Write(alertBuffer);

                var record = new CipherTextRecord(alertBuffer)
                {
                    Type = ERecordType.APPLICATION_DATA,
                    Epoch = 3,
                    RecordNumber = Interlocked.Increment(ref _recordNumberCounter),
                    ConnectionId = _connectionId
                };
                var recordBuffer = new byte[record.Length()];
                record.EncryptAndWrite(recordBuffer, _localAes, _localAesIV, _localAesHeader, true, false);
                await _transport.SendAsync(RemoteEndpoint, recordBuffer, ct);
            }
            catch (OperationCanceledException)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Debug))
                    _logger.LogDebug("Sending close_notify cancelled (connectionId={connectionId})", ConnectionId);
            }
            catch (Exception e)
            {
                if (_logger is not null && _logger.IsEnabled(LogLevel.Error))
                    _logger.LogError(e, "Failed to notify remote on disconnect (connectionId={connectionId})", ConnectionId);
            }
        }

        if (_logger is not null && _logger.IsEnabled(LogLevel.Information))
            _logger.LogInformation("Disconnected (connectionId={connectionId})", ConnectionId);
    }

    public async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _reliableKcp.OnLogMessage += ReliableKcp_OnLogMessage;
            _streamKcp.OnLogMessage += StreamKcp_OnLogMessage;

            _cts.Cancel();
            _cts.Dispose();

            _connectedTcs.TrySetResult();

            _localAes?.Dispose();
            _localAes = null;

            _localAesHeader?.Dispose();
            _localAesHeader = null;

            _remoteAes?.Dispose();
            _remoteAes = null;

            _remoteAesHeader?.Dispose();
            _remoteAesHeader = null;

            await _reliableKcp.StopAsync();
            await _reliableKcp.DisposeAsync();

            await _streamKcp.StopAsync();
            await _streamKcp.DisposeAsync();

            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }

    public void Dispose()
    {
        if (!_disposed)
        {
            _reliableKcp.OnLogMessage += ReliableKcp_OnLogMessage;
            _streamKcp.OnLogMessage += StreamKcp_OnLogMessage;

            _cts.Cancel();
            _cts.Dispose();

            _connectedTcs.TrySetResult();

            _localAes?.Dispose();
            _localAes = null;

            _localAesHeader?.Dispose();
            _localAesHeader = null;

            _remoteAes?.Dispose();
            _remoteAes = null;

            _remoteAesHeader?.Dispose();
            _remoteAesHeader = null;

            _reliableKcp.Dispose();
            _streamKcp.Dispose();

            _disposed = true;
        }
        GC.SuppressFinalize(this);
    }
}
