namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;

public class AdvertiseExtraPacket : Packet
{
    public const EPacketType TYPE = EPacketType.ADVERTISE_EXTRA;
    public override EPacketType Type => TYPE;

    public required Guid ProjectId { get; init; }

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

        len += BinaryHelper.BytesCount(ProjectId);

        len += 1; // Tag

        len += BinaryHelper.BytesCount(Data);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(ProjectId, buffer, ref offset);

        buffer[offset++] = Tag;

        BinaryHelper.Write(Data, buffer, ref offset);
    }

    public static AdvertiseExtraPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var projectId = BinaryHelper.ReadGuid(buffer, ref offset);

            var tag = buffer[offset++];

            var data = BinaryHelper.ReadByteArray(buffer, ref offset);

            return new AdvertiseExtraPacket
            {
                ProjectId = projectId,
                Tag = tag,
                Data = data
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(AdvertiseExtraPacket));
        }
    }
}
