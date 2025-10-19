namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;

public class UnsubscribePacket_Tests
{
    private static UnsubscribePacket CreateRandomUnsubscribePacket()
        => new UnsubscribePacket
        {
            ProjectId = Guid.NewGuid()
        };

    private static string RandomAsciiString(int length)
    {
        var chars = new char[length];
        for (int i = 0; i < length; i++)
            chars[i] = (char)Random.Shared.Next(32, 127);
        return new string(chars);
    }

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomUnsubscribePacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<UnsubscribePacket>(Packet.Parse(buffer));

        Assert.Equal(packet.ProjectId, parsed.ProjectId);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomUnsubscribePacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<UnsubscribePacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomUnsubscribePacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
