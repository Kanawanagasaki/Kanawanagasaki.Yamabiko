namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System;
using System.Security.Cryptography;

public class ConnectDenyPacket_Tests
{
    private static ConnectDenyPacket CreateRandomConnectDenyPacket()
        => new ConnectDenyPacket
        {
            ConnectionId = BitConverter.ToUInt32(RandomNumberGenerator.GetBytes(4)),
            PeerId = Guid.NewGuid(),
            Reason = Random.Shared.NextDouble() < 0.5 ? null : RandomAsciiString(Random.Shared.Next(0, 200))
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
        var packet = CreateRandomConnectDenyPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<ConnectDenyPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.ConnectionId, parsed.ConnectionId);
        Assert.Equal(packet.PeerId, parsed.PeerId);
        Assert.Equal(packet.Reason, parsed.Reason);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomConnectDenyPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<ConnectDenyPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomConnectDenyPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
