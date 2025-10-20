namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;

public class UnsubscribePacket : Packet
{
    public const EPacketType TYPE = EPacketType.UNSUBSCRIBE;
    public override EPacketType Type => TYPE;

    public required Guid ProjectId { get; init; }

    protected override int InternalLength()
        => BinaryHelper.BytesCount(ProjectId);

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;
        BinaryHelper.Write(ProjectId, buffer, ref offset);
    }

    public static UnsubscribePacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;
            var projectId = BinaryHelper.ReadGuid(buffer, ref offset);

            return new UnsubscribePacket
            {
                ProjectId = projectId
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(UnsubscribePacket));
        }
    }
}
