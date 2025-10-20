namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Net;
using System.Security.Cryptography;

public class DirectConnectPacket_Tests
{
    private static DirectConnectPacket CreateRandomDirectConnectPacket()
        => new DirectConnectPacket
        {
            PublicKey = RandomNumberGenerator.GetBytes(32),
            Ip = new IPAddress(RandomNumberGenerator.GetBytes(4)),
            Port = (ushort)Random.Shared.Next(0, ushort.MaxValue)
        };

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomDirectConnectPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<DirectConnectPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.PublicKey, parsed.PublicKey);
        Assert.Equal(packet.Ip, parsed.Ip);
        Assert.Equal(packet.Port, parsed.Port);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomDirectConnectPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<DirectConnectPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomDirectConnectPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
