namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;
using System.Net;

public class PeerConnectPacket : Packet
{
    public const EPacketType TYPE = EPacketType.PEER_CONNECT;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    public required Guid ConnectionId { get; init; }

    private byte[] _publicKey = Array.Empty<byte>();
    public required byte[] PublicKey
    {
        get => _publicKey;
        init
        {
            if (value.Length != 32)
                throw new FormatException("Public key must be 32 bytes long");
            _publicKey = value;
        }
    }

    public required IPAddress Ip { get; init; }
    public required ushort Port { get; init; }

    public byte[]? Extra { get; init; }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(PeerId);

        len += BinaryHelper.BytesCount(ConnectionId);

        len += BinaryHelper.BytesCount(PublicKey);

        len += BinaryHelper.BytesCount(Ip);

        len += BinaryHelper.BytesCount(Port);

        len += BinaryHelper.BytesCount(Extra);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(PeerId, buffer, ref offset);

        BinaryHelper.Write(ConnectionId, buffer, ref offset);

        BinaryHelper.Write(PublicKey, buffer, ref offset);

        BinaryHelper.Write(Ip, buffer, ref offset);

        BinaryHelper.Write(Port, buffer, ref offset);

        BinaryHelper.Write(Extra, buffer, ref offset);
    }

    public static PeerConnectPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var peerId = BinaryHelper.ReadGuid(buffer, ref offset);

            var connectionId = BinaryHelper.ReadGuid(buffer, ref offset);

            var publicKey = BinaryHelper.ReadByteArray(buffer, ref offset);

            var ip = BinaryHelper.ReadIPAddress(buffer, ref offset);

            var port = BinaryHelper.ReadUInt16(buffer, ref offset);

            var extra = BinaryHelper.ReadByteArray(buffer, ref offset);

            return new PeerConnectPacket
            {
                PeerId = peerId,
                ConnectionId = connectionId,
                PublicKey = publicKey ?? Array.Empty<byte>(),
                Ip = ip,
                Port = port,
                Extra = extra
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(PeerConnectPacket));
        }
    }
}
