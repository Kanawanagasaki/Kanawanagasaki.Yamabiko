namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;

public class QueryPacket : Packet
{
    public const EPacketType TYPE = EPacketType.QUERY;
    public override EPacketType Type => TYPE;

    public required Guid ProjectId { get; init; }

    public ulong Flags { get; init; }

    public EProtectionLevel ProtectionLevel { get; init; } = EProtectionLevel.ALL;

    public EOrderBy OrderBy { get; init; } = EOrderBy.NAME_ASC;

    public ushort Skip { get; init; } = 0;

    public byte Count { get; init; } = 24;

    protected override int InternalLength()
    {
        int len = 0;

        len += 16; // project id

        len += 8; // flags

        len += 1; // protection level

        len += 1; // order by

        len += 2; // skip

        len += 1; // count

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        ProjectId.TryWriteBytes(buffer.Slice(offset, 16), true, out _);
        offset += 16;

        buffer[offset++] = (byte)((Flags >> 56) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 48) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 40) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 32) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 24) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 16) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 8) & 0xFF);
        buffer[offset++] = (byte)(Flags & 0xFF);

        buffer[offset++] = (byte)ProtectionLevel;

        buffer[offset++] = (byte)OrderBy;

        buffer[offset++] = (byte)((Skip >> 8) & 0xFF);
        buffer[offset++] = (byte)(Skip & 0xFF);

        buffer[offset++] = Count;
    }

    public static QueryPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        int offset = 0;

        if (buffer.Length < offset + 16)
            throw new FormatException("Buffer too small: cannot read project ID");

        var projectId = new Guid(buffer.Slice(offset, 16), true);
        offset += 16;

        if (buffer.Length < offset + 8)
            throw new FormatException("Buffer too small: cannot read flags");
        var flags = ((ulong)buffer[offset++] << 56)
                  | ((ulong)buffer[offset++] << 48)
                  | ((ulong)buffer[offset++] << 40)
                  | ((ulong)buffer[offset++] << 32)
                  | ((ulong)buffer[offset++] << 24)
                  | ((ulong)buffer[offset++] << 16)
                  | ((ulong)buffer[offset++] << 8)
                  | buffer[offset++];

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read protection level");
        var protectionLevel = (EProtectionLevel)buffer[offset++];

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read order by");
        var orderBy = (EOrderBy)buffer[offset++];

        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too small: cannot read page");
        var skip = (ushort)((buffer[offset++] << 8) | buffer[offset++]);

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read count");
        var count = buffer[offset++];

        return new QueryPacket
        {
            ProjectId = projectId,
            Flags = flags,
            ProtectionLevel = protectionLevel,
            OrderBy = orderBy,
            Skip = skip,
            Count = count
        };
    }
}
