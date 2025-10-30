namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;

public class EmptyQueryResultPacket_Tests
{
    private static EmptyQueryResultPacket CreateRandomEmptyQueryResultPacket()
        => new EmptyQueryResultPacket
        {
            RequestId = Guid.NewGuid(),
            Total = Random.Shared.Next()
        };

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomEmptyQueryResultPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<EmptyQueryResultPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.RequestId, parsed.RequestId);
        Assert.Equal(packet.Total, parsed.Total);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomEmptyQueryResultPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<EmptyQueryResultPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomEmptyQueryResultPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
