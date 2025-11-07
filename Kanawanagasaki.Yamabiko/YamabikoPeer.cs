namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using Kanawanagasaki.Yamabiko.Exceptions;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Buffers;
using System.Diagnostics;
using System.Net;
using System.Security.Cryptography;
using System.Threading.Channels;

public class YamabikoPeer : IAsyncDisposable, IDisposable
{
    public event Action<Exception>? OnError;

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

    private bool _disposed;

    public YamabikoPeer(YamabikoTransport transport, uint connectionId, Guid peerId)
    {
        _transport = transport;
        ConnectionId = connectionId;
        RemotePeerId = peerId;

        _privateKey = RandomNumberGenerator.GetBytes(32);
        PublicKey = KeyHashHelper.GenerateX25519PublicKey(_privateKey);

        _unreliableChannel = Channel.CreateBounded<ReadOnlyMemory<byte>>(new BoundedChannelOptions(128)
        {
            FullMode = BoundedChannelFullMode.DropOldest
        });

        _reliableKcp = new ReliableTransport(this, ConnectionId);
        _reliableKcp.SetNoDelay(true, 10, 2, false);
        _reliableKcp.SetWindowSize(128, 256);
        _reliableKcp.SetMtu(1300);
        _reliableKcp.Start();

        _streamKcp = new ReliableTransport(this, ConnectionId);
        _streamKcp.SetStreamMode(true);
        _streamKcp.SetInterval(25);
        _streamKcp.SetWindowSize(1024, 2048);
        _streamKcp.SetMtu(1300);
        _streamKcp.Start();

        Task.Run(ReceiveLoopAsync);
        Task.Run(PingLoop);
    }

    public YamabikoPeer(YamabikoTransport transport, Guid peerId) : this(transport, BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)), peerId) { }

    internal void ProcessPeerConnect(PeerConnectPacket peerConnect)
    {
        if (ConnectionState is not EConnectionState.HANDSHAKE)
            return;

        ConnectionState = EConnectionState.CONNECTING;
        DeriveKeys(peerConnect.PublicKey);
        RemoteEndpoint = new IPEndPoint(peerConnect.Ip, peerConnect.Port);
    }

    internal void ProcessDirectConnect(DirectConnectPacket directConnect)
    {
        if (ConnectionState is not EConnectionState.HANDSHAKE)
            return;

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

        var peer1HandshakeTraffic = KeyHashHelper.DeriveSecret(handshakeSecret, "c hs traffic", transcriptHash, KeyHashHelper.DTLS_PREFIX);
        var peer2HandshakeTraffic = KeyHashHelper.DeriveSecret(handshakeSecret, "s hs traffic", transcriptHash, KeyHashHelper.DTLS_PREFIX);

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

    internal void ProcessConnectDeny(ConnectDenyPacket connectDeny)
    {
        DenyReason = connectDeny.Reason;
        Disconnect();
    }

    private async Task ReceiveLoopAsync()
    {
        while (!_cts.IsCancellationRequested && ConnectionState is not EConnectionState.DISCONNECTED)
        {
            try
            {
                var buffer = await _transport.ReceiveFromConnectionIdAsync(ConnectionId, _cts.Token);
                await ProcessBufferAsync(buffer);
            }
            catch (Exception e)
            {
                OnError?.Invoke(e);
            }
        }

        ConnectionState = EConnectionState.DISCONNECTED;
    }

    private async Task ProcessBufferAsync(ReadOnlyMemory<byte> buffer)
    {
        if (ConnectionState is EConnectionState.DISCONNECTED)
            return;

        if (_remoteAes is null || _remoteAesIV is null || _remoteAesHeader is null)
            return;

        int offset = 0;
        var record = CipherTextRecord.DecryptAndParse(buffer.Span, _remoteAes, _remoteAesIV, _remoteAesHeader, 0, _lastPeerRecordNumber, 4, ref offset);
        if (_lastPeerRecordNumber < record.RecordNumber)
            _lastPeerRecordNumber = record.RecordNumber;

        _lastActivity = Stopwatch.GetTimestamp();

        if (ConnectionState is EConnectionState.CONNECTING)
        {
            ConnectionState = EConnectionState.CONNECTED;
            _connectedTcs.TrySetResult();
        }

        switch (record.Type)
        {
            case ERecordType.ALERT:
                var alert = Alert.Parse(record.Buffer.Span);
                ProcessAlert(alert);
                break;
            case ERecordType.APPLICATION_DATA:
                await ProcessRecordAsync(record, _cts.Token);
                break;
        }
    }

    private void ProcessAlert(Alert alert)
    {
        if (alert.Type is EAlertType.CLOSE_NOTIFY)
            Disconnect();
    }

    private async Task ProcessRecordAsync(CipherTextRecord record, CancellationToken ct)
    {
        if (record.Buffer.Length == 0)
            return;

        switch ((EPeerPacketType)record.Buffer.Span[0])
        {
            case EPeerPacketType.PING:
                await ProcessPingAsync(record.Buffer[1..], ct);
                break;
            case EPeerPacketType.PONG:
                ProcessPong();
                break;
            case EPeerPacketType.UNRELIABLE:
                await _unreliableChannel.Writer.WriteAsync(record.Buffer[1..], ct);
                break;
            case EPeerPacketType.RELIABLE:
                _reliableKcp.Input(record.Buffer[1..]);
                break;
            case EPeerPacketType.STREAM:
                _streamKcp.Input(record.Buffer[1..]);
                break;
            default:
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

        await EncryptAndSendBufferAsync(EPeerPacketType.PONG, buffer, ct);
    }

    private void ProcessPong()
    {
        if (0 < _pingLastTime)
        {
            Ping = Stopwatch.GetElapsedTime(_pingLastTime);
            _pingLastTime = -1;
        }
    }

    private async Task PingLoop()
    {
        using var timer = new PeriodicTimer(PingInterval);
        do
        {
            await PingAsync(_cts.Token);

            _reliableKcp.Flush();
            _streamKcp.Flush();

            if (ConnectionState is EConnectionState.CONNECTED && Timeout < Stopwatch.GetElapsedTime(_lastActivity))
                Disconnect();
        }
        while (!_cts.IsCancellationRequested && await timer.WaitForNextTickAsync(_cts.Token) && ConnectionState is not EConnectionState.DISCONNECTED);

        ConnectionState = EConnectionState.DISCONNECTED;
    }

    internal async Task PingAsync(CancellationToken ct = default)
    {
        _pingLastTime = Stopwatch.GetTimestamp();
        await EncryptAndSendBufferAsync(EPeerPacketType.PING, Array.Empty<byte>(), ct);
    }

    public Task SendUnreliableAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
        => EncryptAndSendBufferAsync(EPeerPacketType.UNRELIABLE, buffer, ct);

    public async Task<ReadOnlyMemory<byte>> ReceiveUnreliableAsync(CancellationToken ct = default)
        => await _unreliableChannel.Reader.ReadAsync(ct);

    public void SendReliable(ReadOnlyMemory<byte> buffer)
        => _reliableKcp.Write(buffer);

    public ValueTask<ReadOnlyMemory<byte>> ReceiveReliableAsync(CancellationToken ct = default)
        => _reliableKcp.ReadAsync(ct);

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
                throw new TimeoutException("Connection has timed out");
            if (ConnectionState is EConnectionState.DISCONNECTED)
                throw new DisconnectedException("Peer disconnected");
        }
        finally
        {
            linkedCts.Cancel();
        }
    }

    public void Disconnect()
    {
        ConnectionState = EConnectionState.DISCONNECTED;
        _cts.Cancel();
        _connectedTcs.TrySetResult();
    }

    public async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            Disconnect();

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
            Disconnect();

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
