namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using System;

public class SubscribePacket : Packet
{
    public const EPacketType TYPE = EPacketType.SUBSCRIBE;
    public override EPacketType Type => TYPE;

    public required Guid ProjectId { get; init; }

    protected override int InternalLength()
        => 16;

    protected override void InternalWrite(Span<byte> buffer)
    {
        ProjectId.TryWriteBytes(buffer, true, out _);
    }

    public static SubscribePacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 16)
            throw new FormatException("Buffer too short: cannot read project id");

        var projectId = new Guid(buffer.Slice(0, 16), true);

        return new SubscribePacket
        {
            ProjectId = projectId
        };
    }
}
