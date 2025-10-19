namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;

public class PingPacket : Packet
{
    public const EPacketType TYPE = EPacketType.PING;
    public override EPacketType Type => TYPE;

    protected override int InternalLength()
        => 4;

    protected override void InternalWrite(Span<byte> buffer)
    {
        buffer[0] = (byte)'P';
        buffer[1] = (byte)'I';
        buffer[2] = (byte)'N';
        buffer[3] = (byte)'G';
    }

    public static PingPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length != 4)
            throw new FormatException("Buffer has incorrect size");

        if (buffer[0] != (byte)'P' || buffer[1] != (byte)'I' || buffer[2] != (byte)'N' || buffer[3] != (byte)'G')
            throw new FormatException("Invalid ping message");

        return new PingPacket();
    }
}
