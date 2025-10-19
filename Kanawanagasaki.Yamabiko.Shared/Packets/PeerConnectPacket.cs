namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using System;
using System.Net;
using System.Net.Sockets;

public class PeerConnectPacket : Packet
{
    public const EPacketType TYPE = EPacketType.PEER_CONNECT;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    public required byte[] PublicKey { get; init; }

    public required IPAddress Ip { get; init; }
    public required ushort Port { get; init; }
    
    protected override int InternalLength()
    {
        int len = 0;

        len += 16;

        len += 1 + PublicKey.Length;

        len += 1 + (Ip.AddressFamily is AddressFamily.InterNetwork ? 4 : 16);

        len += 2; // port

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        PeerId.TryWriteBytes(buffer.Slice(offset, 16), true, out _);
        offset += 16;

        buffer[offset++] = (byte)PublicKey.Length;
        PublicKey.AsSpan(0, (byte)PublicKey.Length).CopyTo(buffer.Slice(offset, (byte)PublicKey.Length));
        offset += (byte)PublicKey.Length;

        var ipLength = Ip.AddressFamily is AddressFamily.InterNetwork ? (byte)4 : (byte)16;
        buffer[offset++] = ipLength;
        Ip.TryWriteBytes(buffer.Slice(offset, ipLength), out _);
        offset += ipLength;

        buffer[offset++] = (byte)((Port >> 8) & 0xFF);
        buffer[offset++] = (byte)(Port & 0xFF);
    }

    public static PeerConnectPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        int offset = 0;

        if (buffer.Length < offset + 16)
            throw new FormatException("Buffer too short: cannot read peer id");
        var peerId = new Guid(buffer.Slice(0, 16), true);
        offset += 16;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too short: cannot read public key length");
        var publicKeyLength = buffer[offset++];
        if (buffer.Length < offset + publicKeyLength)
            throw new FormatException("Buffer too short: cannot read public key");
        var publicKeySpan = buffer.Slice(offset, publicKeyLength);
        offset += publicKeyLength;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too short: cannot read ip length");
        var ipLength = buffer[offset++];
        if (buffer.Length < offset + ipLength)
            throw new FormatException("Buffer too short: cannot read ip");
        var ip = new IPAddress(buffer.Slice(offset, ipLength));
        offset += ipLength;

        var port = (ushort)((buffer[offset++] << 8) | buffer[offset++]);

        return new PeerConnectPacket
        {
            PeerId = peerId,
            PublicKey = publicKeySpan.ToArray(),
            Ip = ip,
            Port = port
        };
    }
}
