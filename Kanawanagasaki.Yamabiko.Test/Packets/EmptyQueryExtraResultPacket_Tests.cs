namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Security.Cryptography;

public class EmptyQueryExtraResultPacket_Tests
{
    private static EmptyQueryExtraResultPacket CreateRandomEmptyQueryExtraResultPacket()
        => new EmptyQueryExtraResultPacket
        {
            RequestId = Guid.NewGuid(),
            PeerId = Guid.NewGuid(),
            TagsIds = RandomNumberGenerator.GetBytes(Random.Shared.Next(1, 256))
        };

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomEmptyQueryExtraResultPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<EmptyQueryExtraResultPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.RequestId, parsed.RequestId);
        Assert.Equal(packet.PeerId, parsed.PeerId);
        Assert.Equal(packet.TagsIds, parsed.TagsIds);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomEmptyQueryExtraResultPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<EmptyQueryExtraResultPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomEmptyQueryExtraResultPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
