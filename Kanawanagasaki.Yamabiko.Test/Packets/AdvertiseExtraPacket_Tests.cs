namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Security.Cryptography;

public class AdvertiseExtraPacket_Tests
{
    private static AdvertiseExtraPacket CreateRandomAdvertiseExtraPacket()
        => new AdvertiseExtraPacket
        {
            Tag = (byte)Random.Shared.Next(0, 256),
            Data = RandomNumberGenerator.GetBytes(255)
        };

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomAdvertiseExtraPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<AdvertiseExtraPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.Tag, parsed.Tag);
        Assert.Equal(packet.Data, parsed.Data);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomAdvertiseExtraPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<AdvertiseExtraPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomAdvertiseExtraPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
