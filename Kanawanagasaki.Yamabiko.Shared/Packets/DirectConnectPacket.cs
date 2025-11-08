namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;
using System.Net;

public class DirectConnectPacket : Packet
{
    public const EPacketType TYPE = EPacketType.DIRECT_CONNECT;
    public override EPacketType Type => TYPE;

    public required uint ConnectionId { get; init; }

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

    public required IPAddress LanIp { get; init; }
    public required ushort LanPort { get; init; }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(ConnectionId);

        len += BinaryHelper.BytesCount(PublicKey);

        len += BinaryHelper.BytesCount(Ip);

        len += BinaryHelper.BytesCount(Port);

        len += BinaryHelper.BytesCount(LanIp);

        len += BinaryHelper.BytesCount(LanPort);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(ConnectionId, buffer, ref offset);

        BinaryHelper.Write(PublicKey, buffer, ref offset);

        BinaryHelper.Write(Ip, buffer, ref offset);

        BinaryHelper.Write(Port, buffer, ref offset);

        BinaryHelper.Write(LanIp, buffer, ref offset);

        BinaryHelper.Write(LanPort, buffer, ref offset);
    }

    public static DirectConnectPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var connectionId = BinaryHelper.ReadUInt32(buffer, ref offset);

            var publicKey = BinaryHelper.ReadByteArray(buffer, ref offset);

            var ip = BinaryHelper.ReadIPAddress(buffer, ref offset);

            var port = BinaryHelper.ReadUInt16(buffer, ref offset);

            var lanIp = BinaryHelper.ReadIPAddress(buffer, ref offset);

            var lanPort = BinaryHelper.ReadUInt16(buffer, ref offset);

            return new DirectConnectPacket
            {
                ConnectionId = connectionId,
                PublicKey = publicKey ?? Array.Empty<byte>(),
                Ip = ip,
                Port = port,
                LanIp = lanIp,
                LanPort = lanPort
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(ConnectPacket));
        }
    }
}
