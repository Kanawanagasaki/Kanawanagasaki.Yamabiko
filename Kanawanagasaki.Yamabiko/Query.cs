namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using Kanawanagasaki.Yamabiko.Tags;

public class Query
{
    public ulong Flags { get; init; }
    public EProtectionLevel ProtectionLevel { get; init; } = EProtectionLevel.ANY;
    public EOrderBy OrderBy { get; init; } = EOrderBy.NAME_ASC;
    public ITag? FilterTag { get; init; }
    public EFilterOperation FilterOperation { get; init; } = EFilterOperation.EQUALS;
    public ushort Skip { get; init; } = 0;
    public byte Count { get; init; } = 24;

    private Guid _requestId = Guid.NewGuid();

    public QueryPacket ToPacket(Guid projectId)
        => new QueryPacket
        {
            ProjectId = projectId,
            RequestId = _requestId,
            Flags = Flags,
            ProtectionLevel = ProtectionLevel,
            OrderBy = OrderBy,
            FilterTag = FilterTag?.TagId ?? 0,
            Filter = FilterTag?.ToByteArray(),
            FilterOperation = FilterOperation,
            Skip = Skip,
            Count = Count
        };
}
