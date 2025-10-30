namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Security.Cryptography;

public class PeerPacket_Tests
{
    private static PeerPacket CreateRandomPeerPacket()
        => new PeerPacket
        {
            PeerId = Guid.NewGuid(),
            ProjectId = Guid.NewGuid(),
            Name = RandomAsciiString(Random.Shared.Next(0, 200)),
            Flags = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8), 0),
            ExtraTags = RandomNumberGenerator.GetBytes(255).Distinct().ToArray(),
            ProtectionLevel = Random.Shared.NextDouble() < 0.5 ? EProtectionLevel.PUBLIC : EProtectionLevel.PASSWORD_PROTECTED,
            RequestId = Guid.NewGuid(),
            Index = Random.Shared.Next(0, int.MaxValue),
            Total = Random.Shared.Next(0, int.MaxValue),
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
        var packet = CreateRandomPeerPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<PeerPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.PeerId, parsed.PeerId);
        Assert.Equal(packet.ProjectId, parsed.ProjectId);
        Assert.Equal(packet.Name, parsed.Name);
        Assert.Equal(packet.Flags, parsed.Flags);
        Assert.Equal(packet.ExtraTags, parsed.ExtraTags);
        Assert.Equal(packet.ProtectionLevel, parsed.ProtectionLevel);
        Assert.Equal(packet.RequestId, parsed.RequestId);
        Assert.Equal(packet.Index, parsed.Index);
        Assert.Equal(packet.Total, parsed.Total);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomPeerPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<PeerPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomPeerPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
