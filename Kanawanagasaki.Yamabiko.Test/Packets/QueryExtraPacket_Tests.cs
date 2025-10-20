namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Security.Cryptography;

public class QueryExtraPacket_Tests
{
    private static QueryExtraPacket CreateRandomQueryExtraPacket()
        => new QueryExtraPacket
        {
            PeerId = Guid.NewGuid(),
            ExtraTags = RandomNumberGenerator.GetBytes(255).Distinct().ToArray(),
        };

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomQueryExtraPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<QueryExtraPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.PeerId, parsed.PeerId);
        Assert.Equal(packet.ExtraTags, parsed.ExtraTags);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomQueryExtraPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<QueryExtraPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomQueryExtraPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
