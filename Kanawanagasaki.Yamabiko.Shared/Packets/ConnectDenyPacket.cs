namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;

public class ConnectDenyPacket : Packet
{
    public const EPacketType TYPE = EPacketType.CONNECT_DENY;
    public override EPacketType Type => TYPE;

    public required uint ConnectionId { get; init; }

    public required Guid PeerId { get; init; }

    private string? _reason;
    public string? Reason
    {
        get => _reason;
        init
        {
            if (value is not null && 255 < BinaryHelper.BytesCount(value))
                throw new FormatException("Reason is too long");
            _reason = value;
        }
    }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(ConnectionId);

        len += BinaryHelper.BytesCount(PeerId);

        len += BinaryHelper.BytesCount(Reason);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(ConnectionId, buffer, ref offset);

        BinaryHelper.Write(PeerId, buffer, ref offset);

        BinaryHelper.Write(Reason, buffer, ref offset);
    }

    public static ConnectDenyPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var connectionId = BinaryHelper.ReadUInt32(buffer, ref offset);

            var peerId = BinaryHelper.ReadGuid(buffer, ref offset);

            var reason = BinaryHelper.ReadString(buffer, ref offset);

            return new ConnectDenyPacket
            {
                ConnectionId = connectionId,
                PeerId = peerId,
                Reason = reason
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(ConnectDenyPacket));
        }
    }
}
