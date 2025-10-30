namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;

public class EmptyQueryExtraResultPacket : Packet
{
    public const EPacketType TYPE = EPacketType.EMPTY_QUERY_EXTRA_RESULT;
    public override EPacketType Type => TYPE;

    public required Guid RequestId { get; init; }

    public required Guid PeerId { get; init; }

    public byte[] _tagsIds = Array.Empty<byte>();
    public byte[] TagsIds
    {
        get => _tagsIds;
        init
        {
            if (255 < value.Length)
                throw new FormatException("Tags Ids is too long");
            _tagsIds = value;
        }
    }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(RequestId);

        len += BinaryHelper.BytesCount(PeerId);

        len += BinaryHelper.BytesCount(TagsIds);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(RequestId, buffer, ref offset);

        BinaryHelper.Write(PeerId, buffer, ref offset);

        BinaryHelper.Write(TagsIds, buffer, ref offset);
    }

    public static EmptyQueryExtraResultPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var requestId = BinaryHelper.ReadGuid(buffer, ref offset);

            var peerId = BinaryHelper.ReadGuid(buffer, ref offset);

            var tagsIds = BinaryHelper.ReadByteArray(buffer, ref offset);

            return new EmptyQueryExtraResultPacket
            {
                RequestId = requestId,
                PeerId = peerId,
                TagsIds = tagsIds ?? Array.Empty<byte>()
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(EmptyQueryExtraResultPacket));
        }
    }
}
