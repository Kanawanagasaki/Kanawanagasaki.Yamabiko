namespace Kanawanagasaki.Yamabiko;

using KcpSharp;
using System.Buffers;
using System.Threading;
using System.Threading.Tasks;

public class KcpTransport : IKcpTransport, IDisposable
{
    public KcpConversation Conversation { get; }

    private readonly YamabikoPeer _peer;
    private readonly SemaphoreSlim _semaphore;
    private readonly bool _isStreamMode;

    public KcpTransport(YamabikoPeer peer, int mtu, bool isStreamMode)
    {
        Conversation = new KcpConversation(this, new()
        {
            Mtu = mtu,
            SendWindow = 128,
            ReceiveWindow = 256,
            StreamMode = isStreamMode
        });

        _peer = peer;
        _semaphore = new SemaphoreSlim(1, 1);
        _isStreamMode = isStreamMode;
    }

    public async ValueTask SendPacketAsync(Memory<byte> packet, CancellationToken ct)
    {
        await _peer.EncryptAndSendBufferAsync(_isStreamMode ? EPeerPacketType.STREAM : EPeerPacketType.RELIABLE, packet, ct);
    }

    public async Task InputPacketAsync(ReadOnlyMemory<byte> packet, CancellationToken ct)
    {
        await Conversation.InputPakcetAsync(packet, ct);
    }

    public async Task WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        await _semaphore.WaitAsync(ct);
        try
        {
            await Conversation.SendAsync(buffer, ct);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public async Task FlushAsync(CancellationToken ct)
    {
        await _semaphore.WaitAsync(ct);
        try
        {
            await Conversation.FlushAsync(ct);
        }
        finally
        {
            _semaphore.Release();
        }
    }

    public async Task<ReadOnlyMemory<byte>> ReadAsync(CancellationToken ct)
    {
        const int bufferSize = (1400 - 24) * 256;
        var rentedBuffer = ArrayPool<byte>.Shared.Rent(bufferSize);
        var buffer = rentedBuffer.AsMemory(0, bufferSize);
        try
        {
            var result = await Conversation.ReceiveAsync(buffer, ct);
            if (result.TransportClosed)
                return Array.Empty<byte>();

            return buffer[..result.BytesReceived];
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(rentedBuffer);
        }
    }

    public void Dispose()
    {
        Conversation.Dispose();
        _semaphore.Dispose();
    }
}
