namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;

public abstract class YamabikoTransport : IAsyncDisposable, IDisposable
{
    private static readonly BoundedChannelOptions _boundedChannelOptions
        = new BoundedChannelOptions(128) { FullMode = BoundedChannelFullMode.DropOldest };

    private static readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan _channelInactivityTimeout = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<IPEndPoint, Channel<ReadOnlyMemory<byte>>> _endpointChannels;
    private readonly ConcurrentDictionary<IPEndPoint, long> _endpointLastActivityTimestamps;
    private readonly ConcurrentDictionary<uint, Channel<ReadOnlyMemory<byte>>> _connectionIdChannels;
    private readonly ConcurrentDictionary<uint, long> _connectionIdActivityTimestamps;

    private readonly CancellationTokenSource _cts;
    private readonly Task _receiveLoopTask;
    private readonly Task _cleanupLoopTask;

    public YamabikoTransport()
    {
        _endpointChannels = new();
        _endpointLastActivityTimestamps = new();
        _connectionIdChannels = new();
        _connectionIdActivityTimestamps = new();
        _cts = new CancellationTokenSource();
        Init();
        _receiveLoopTask = Task.Run(ReceiveLoopAsync);
        _cleanupLoopTask = Task.Run(CleanupInactiveChannelsAsync);
    }

    private async Task ReceiveLoopAsync()
    {
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var result = await ReceiveAsync(_cts.Token);
                var now = Stopwatch.GetTimestamp();

                if (CipherTextRecord.TryReadConnectionId(result.Buffer.Span, 4, out var connectionIdBytes))
                {
                    int offset = 0;
                    var connectionId = BinaryHelper.ReadUInt32(connectionIdBytes, ref offset);

                    _connectionIdActivityTimestamps.AddOrUpdate(connectionId, now, (_, _) => now);
                    var channel = _connectionIdChannels.GetOrAdd(connectionId, _ => Channel.CreateBounded<ReadOnlyMemory<byte>>(_boundedChannelOptions));
                    await channel.Writer.WriteAsync(result.Buffer);
                }
                else
                {
                    _endpointLastActivityTimestamps.AddOrUpdate(result.RemoteEndPoint, now, (_, _) => now);
                    var channel = _endpointChannels.GetOrAdd(result.RemoteEndPoint, _ => Channel.CreateBounded<ReadOnlyMemory<byte>>(_boundedChannelOptions));
                    await channel.Writer.WriteAsync(result.Buffer);
                }
            }
            catch (OperationCanceledException) { }
            catch (ChannelClosedException) { }
            catch (SocketException e) when (e.SocketErrorCode is SocketError.ConnectionReset) { }
        }

        foreach (var channel in _endpointChannels.Values)
            channel.Writer.TryComplete();
        _endpointChannels.Clear();

        foreach (var channel in _connectionIdChannels.Values)
            channel.Writer.TryComplete();
        _connectionIdChannels.Clear();
    }

    private async Task CleanupInactiveChannelsAsync()
    {
        using var timer = new PeriodicTimer(_cleanupInterval);
        try
        {
            while (!_cts.IsCancellationRequested && await timer.WaitForNextTickAsync(_cts.Token))
            {
                foreach (var (endpoint, lastActivity) in _endpointLastActivityTimestamps)
                {
                    if (_channelInactivityTimeout < Stopwatch.GetElapsedTime(lastActivity))
                    {
                        if (_endpointChannels.TryRemove(endpoint, out var channel))
                            channel.Writer.TryComplete();
                        _endpointLastActivityTimestamps.TryRemove(endpoint, out _);
                    }
                }
                foreach (var (uuid, lastActivity) in _connectionIdActivityTimestamps)
                {
                    if (_channelInactivityTimeout < Stopwatch.GetElapsedTime(lastActivity))
                    {
                        if (_connectionIdChannels.TryRemove(uuid, out var channel))
                            channel.Writer.TryComplete();
                        _connectionIdActivityTimestamps.TryRemove(uuid, out _);
                    }
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    internal async Task<ReadOnlyMemory<byte>> ReceiveFromEndpointAsync(IPEndPoint endpoint, CancellationToken ct = default)
    {
        if (_receiveLoopTask.IsFaulted)
            ExceptionDispatchInfo.Capture(_receiveLoopTask.Exception).Throw();
        if (_receiveLoopTask.IsCompleted)
            throw new InvalidOperationException("Receive loop has finished");
        if (_cleanupLoopTask.IsFaulted)
            ExceptionDispatchInfo.Capture(_cleanupLoopTask.Exception).Throw();

        var channel = _endpointChannels.GetOrAdd(endpoint, (ep) =>
        {
            _endpointLastActivityTimestamps.TryAdd(ep, Stopwatch.GetTimestamp());
            return Channel.CreateBounded<ReadOnlyMemory<byte>>(_boundedChannelOptions);
        });

        return await channel.Reader.ReadAsync(ct);
    }

    internal async Task<ReadOnlyMemory<byte>> ReceiveFromConnectionIdAsync(uint connectionId, CancellationToken ct = default)
    {
        if (_receiveLoopTask.IsFaulted)
            ExceptionDispatchInfo.Capture(_receiveLoopTask.Exception).Throw();
        if (_receiveLoopTask.IsCompleted)
            throw new InvalidOperationException("Receive loop has finished");
        if (_cleanupLoopTask.IsFaulted)
            ExceptionDispatchInfo.Capture(_cleanupLoopTask.Exception).Throw();

        var channel = _connectionIdChannels.GetOrAdd(connectionId, (uuid) =>
        {
            _connectionIdActivityTimestamps.TryAdd(uuid, Stopwatch.GetTimestamp());
            return Channel.CreateBounded<ReadOnlyMemory<byte>>(_boundedChannelOptions);
        });

        return await channel.Reader.ReadAsync(ct);
    }

    protected abstract void Init();
    public abstract Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct);
    protected abstract Task<YamabikoReceiveResult> ReceiveAsync(CancellationToken ct);

    public abstract ushort GetLanPort();

    public virtual async ValueTask DisposeAsync()
    {
        _cts.Cancel();

        foreach (var channel in _endpointChannels.Values)
            channel.Writer.TryComplete();
        foreach (var channel in _connectionIdChannels.Values)
            channel.Writer.TryComplete();

        try
        {
            await _receiveLoopTask.ConfigureAwait(false);
        }
        catch { }

        try
        {
            await _cleanupLoopTask.ConfigureAwait(false);
        }
        catch { }

        _cts.Dispose();
    }

    public void Dispose()
    {
        _cts.Cancel();

        foreach (var channel in _endpointChannels.Values)
            channel.Writer.TryComplete();
        foreach (var channel in _connectionIdChannels.Values)
            channel.Writer.TryComplete();

        _cts.Dispose();
    }
}
