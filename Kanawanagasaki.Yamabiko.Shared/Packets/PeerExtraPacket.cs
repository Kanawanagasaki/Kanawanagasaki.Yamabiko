namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;

public class PeerExtraPacket : Packet
{
    public const EPacketType TYPE = EPacketType.PEER_EXTRA;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    public required byte Tag { get; init; }

    private byte[]? _data;
    public required byte[]? Data
    {
        get => _data;
        init
        {
            if (value is not null && 255 < value.Length)
                throw new FormatException("Data is too long");
            _data = value;
        }
    }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(PeerId);

        len += 1; // Tag

        len += BinaryHelper.BytesCount(Data);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(PeerId, buffer, ref offset);

        buffer[offset++] = Tag;

        BinaryHelper.Write(Data, buffer, ref offset);
    }

    public static PeerExtraPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var peerId = BinaryHelper.ReadGuid(buffer, ref offset);

            var tag = buffer[offset++];

            var data = BinaryHelper.ReadByteArray(buffer, ref offset);

            return new PeerExtraPacket
            {
                PeerId = peerId,
                Tag = tag,
                Data = data
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(PeerExtraPacket));
        }
    }
}
