namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class EmptyQueryResultPacket : Packet
{
    public const EPacketType TYPE = EPacketType.EMPTY_QUERY_RESULT;
    public override EPacketType Type => TYPE;

    public required Guid RequestId { get; init; }

    public required int Total { get; init; }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(RequestId);

        len += BinaryHelper.BytesCount(Total);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(RequestId, buffer, ref offset);

        BinaryHelper.Write(Total, buffer, ref offset);
    }

    public static EmptyQueryResultPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var requrestId = BinaryHelper.ReadGuid(buffer, ref offset);

            var total = BinaryHelper.ReadInt32(buffer, ref offset);

            return new EmptyQueryResultPacket
            {
                RequestId = requrestId,
                Total = total
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(EmptyQueryResultPacket));
        }
    }
}
