namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Net;
using System.Security.Cryptography;

public class PeerConnectPacket_Tests
{
    private static PeerConnectPacket CreateRandomPeerConnectPacket()
        => new PeerConnectPacket
        {
            PeerId = Guid.NewGuid(),
            ConnectionId = Guid.NewGuid(),
            PublicKey = RandomNumberGenerator.GetBytes(32),
            Ip = new IPAddress(RandomNumberGenerator.GetBytes(4)),
            Port = (ushort)Random.Shared.Next(0, ushort.MaxValue),
            Extra = Random.Shared.NextDouble() < 0.5 ? null : RandomNumberGenerator.GetBytes(Random.Shared.Next(0, 1000))
        };

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomPeerConnectPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<PeerConnectPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.PeerId, parsed.PeerId);
        Assert.Equal(packet.ConnectionId, parsed.ConnectionId);
        Assert.Equal(packet.PublicKey, parsed.PublicKey);
        Assert.Equal(packet.Ip, parsed.Ip);
        Assert.Equal(packet.Port, parsed.Port);
        Assert.Equal(packet.Extra, parsed.Extra);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomPeerConnectPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<PeerConnectPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomPeerConnectPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
