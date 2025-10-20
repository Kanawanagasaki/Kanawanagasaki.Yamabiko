namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System;
using System.Security.Cryptography;

public class AdvertisePacketTests
{
    private static AdvertisePacket CreateRandomAdvertisePacket()
        => new AdvertisePacket
        {
            ProjectId = Guid.NewGuid(),
            Name = RandomAsciiString(Random.Shared.Next(0, 200)),
            Password = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(0, 200)),
            Flags = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8), 0)
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
        var packet = CreateRandomAdvertisePacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<AdvertisePacket>(Packet.Parse(buffer));

        Assert.Equal(packet.ProjectId, parsed.ProjectId);
        Assert.Equal(packet.Name, parsed.Name);
        Assert.Equal(packet.Password, parsed.Password);
        Assert.Equal(packet.Flags, parsed.Flags);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomAdvertisePacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<AdvertisePacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomAdvertisePacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
