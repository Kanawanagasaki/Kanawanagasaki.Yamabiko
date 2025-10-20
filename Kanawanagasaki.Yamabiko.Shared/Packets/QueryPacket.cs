namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class QueryPacket : Packet
{
    public const EPacketType TYPE = EPacketType.QUERY;
    public override EPacketType Type => TYPE;

    public required Guid ProjectId { get; init; }

    public ulong Flags { get; init; }

    public EProtectionLevel ProtectionLevel { get; init; } = EProtectionLevel.ALL;

    public EOrderBy OrderBy { get; init; } = EOrderBy.NAME_ASC;

    public byte FilterTag { get; init; }

    private byte[]? _filter;
    public byte[]? Filter
    {
        get => _filter;
        init
        {
            if (value is not null && 255 < value.Length)
                throw new FormatException("Filter is too long");
            _filter = value;
        }
    }

    public EFilterOperation FilterOperation { get; init; }

    public ushort Skip { get; init; } = 0;

    public byte Count { get; init; } = 24;

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(ProjectId);

        len += BinaryHelper.BytesCount(Flags);

        len += 1; // ProtectionLevel

        len += 1; // OrderBy

        len += 1; // Filter tag

        len += BinaryHelper.BytesCount(Filter);

        len += 1; // Filter operation

        len += BinaryHelper.BytesCount(Skip);

        len += 1; // Count

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(ProjectId, buffer, ref offset);

        BinaryHelper.Write(Flags, buffer, ref offset);

        buffer[offset++] = (byte)ProtectionLevel;

        buffer[offset++] = (byte)OrderBy;

        buffer[offset++] = FilterTag;

        BinaryHelper.Write(Filter, buffer, ref offset);

        buffer[offset++] = (byte)FilterOperation;

        BinaryHelper.Write(Skip, buffer, ref offset);

        buffer[offset++] = Count;
    }

    public static QueryPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var projectId = BinaryHelper.ReadGuid(buffer, ref offset);

            var flags = BinaryHelper.ReadUInt64(buffer, ref offset);

            var protectionLevel = (EProtectionLevel)buffer[offset++];

            var orderBy = (EOrderBy)buffer[offset++];

            var filterTag = buffer[offset++];

            var filter = BinaryHelper.ReadByteArray(buffer, ref offset);

            var filterOp = (EFilterOperation)buffer[offset++];

            var skip = BinaryHelper.ReadUInt16(buffer, ref offset);

            var count = buffer[offset++];

            return new QueryPacket
            {
                ProjectId = projectId,
                Flags = flags,
                ProtectionLevel = protectionLevel,
                OrderBy = orderBy,
                FilterTag = filterTag,
                Filter = filter,
                FilterOperation = filterOp,
                Skip = skip,
                Count = count
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(QueryPacket));
        }
    }
}
