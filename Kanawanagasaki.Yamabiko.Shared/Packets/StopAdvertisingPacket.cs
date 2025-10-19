namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using System;

public class StopAdvertisingPacket : Packet
{
    public const EPacketType TYPE = EPacketType.STOP_ADVERTISING;
    public override EPacketType Type => TYPE;

    protected override int InternalLength()
        => 0;

    protected override void InternalWrite(Span<byte> buffer)
    { }

    public static StopAdvertisingPacket InternalParse(ReadOnlySpan<byte> buffer)
        => new StopAdvertisingPacket();
}
