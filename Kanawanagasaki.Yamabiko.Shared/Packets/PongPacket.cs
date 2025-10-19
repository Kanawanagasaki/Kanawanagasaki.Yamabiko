namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;

public class PongPacket : Packet
{
    public const EPacketType TYPE = EPacketType.PONG;
    public override EPacketType Type => TYPE;

    protected override int InternalLength()
        => 4;

    protected override void InternalWrite(Span<byte> buffer)
    {
        buffer[0] = (byte)'P';
        buffer[1] = (byte)'O';
        buffer[2] = (byte)'N';
        buffer[3] = (byte)'G';
    }

    public static PongPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length != 4)
            throw new FormatException("Buffer has incorrect size");

        if (buffer[0] != (byte)'P' || buffer[1] != (byte)'O' || buffer[2] != (byte)'N' || buffer[3] != (byte)'G')
            throw new FormatException("Invalid pong message");

        return new PongPacket();
    }
}
