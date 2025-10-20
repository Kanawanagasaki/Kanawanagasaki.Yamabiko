namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;

public class QueryExtraPacket : Packet
{
    public const EPacketType TYPE = EPacketType.QUERY_EXTRA;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    public byte[] _extraTags = Array.Empty<byte>();
    public byte[] ExtraTags
    {
        get => _extraTags;
        init
        {
            if (255 < value.Length)
                throw new FormatException("Extra Tags is too long");
            _extraTags = value;
        }
    }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(PeerId);

        len += BinaryHelper.BytesCount(ExtraTags);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(PeerId, buffer, ref offset);

        BinaryHelper.Write(ExtraTags, buffer, ref offset);
    }

    public static QueryExtraPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var peerId = BinaryHelper.ReadGuid(buffer, ref offset);

            var extraTags = BinaryHelper.ReadByteArray(buffer, ref offset);

            return new QueryExtraPacket
            {
                PeerId = peerId,
                ExtraTags = extraTags ?? Array.Empty<byte>(),
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(QueryExtraPacket));
        }
    }
}
