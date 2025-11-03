namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;
using System.Runtime.ExceptionServices;
using System.Threading.Channels;

public abstract class YamabikoTransport : IAsyncDisposable
{
    private static readonly BoundedChannelOptions _boundedChannelOptions
        = new BoundedChannelOptions(128) { FullMode = BoundedChannelFullMode.DropOldest };

    private static readonly TimeSpan _cleanupInterval = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan _channelInactivityTimeout = TimeSpan.FromMinutes(5);

    private readonly ConcurrentDictionary<IPEndPoint, Channel<ReadOnlyMemory<byte>>> _endpointChannels;
    private readonly ConcurrentDictionary<IPEndPoint, long> _endpointLastActivityTimestamps;
    private readonly ConcurrentDictionary<Guid, Channel<ReadOnlyMemory<byte>>> _connectionIdChannels;
    private readonly ConcurrentDictionary<Guid, long> _connectionIdActivityTimestamps;

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

                var connectionIdBytes = CipherTextRecord.ReadConnectionId(result.Buffer.Span, 16, 0);
                if (connectionIdBytes.Length == 16)
                {
                    var connectionId = new Guid(connectionIdBytes, true);
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

    public async Task<ReadOnlyMemory<byte>> ReceiveFromEndpointAsync(IPEndPoint endpoint, CancellationToken ct = default)
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

    public async Task<ReadOnlyMemory<byte>> ReceiveFromConnectionIdAsync(Guid connectionId, CancellationToken ct = default)
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

    public abstract Task SendAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct);
    protected abstract Task<YamabikoReceiveResult> ReceiveAsync(CancellationToken ct);

    public virtual async ValueTask DisposeAsync()
    {
        _cts.Cancel();

        foreach (var channel in _endpointChannels.Values)
            channel.Writer.TryComplete();
        foreach (var channel in _connectionIdChannels.Values)
            channel.Writer.TryComplete();

        Exception? receiveException = null;
        try
        {
            await _receiveLoopTask.ConfigureAwait(false);
        }
        catch (Exception e)
        {
            receiveException = e;
        }

        Exception? cleanupException = null;
        try
        {
            await _cleanupLoopTask.ConfigureAwait(false);
        }
        catch (Exception e)
        {
            cleanupException = e;
        }

        _cts.Dispose();

        if (receiveException is not null || cleanupException is not null)
            throw new AggregateException(new Exception?[] { receiveException, cleanupException }.Where(x => x is not null)!);
    }
}
