namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.KCP;
using System.Threading;
using System.Threading.Tasks;

internal class ReliableTransport : KcpTransport
{
    private readonly YamabikoPeer _peer;

    internal ReliableTransport(YamabikoPeer peer, uint conversationId) : base(conversationId)
    {
        _peer = peer;
    }

    protected override async ValueTask<int> SendAsync(ReadOnlyMemory<byte> data, CancellationToken ct)
    {
        await _peer.EncryptAndSendBufferAsync(IsStreamMode ? EPeerPacketType.STREAM : EPeerPacketType.RELIABLE, data, ct);
        return data.Length;
    }
}
