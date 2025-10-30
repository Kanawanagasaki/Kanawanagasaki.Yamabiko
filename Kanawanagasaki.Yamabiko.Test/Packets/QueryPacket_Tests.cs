namespace Kanawanagasaki.Yamabiko.Test.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Security.Cryptography;

public class QueryPacket_Tests
{
    private static QueryPacket CreateRandomQueryPacket()
        => new QueryPacket
        {
            RequestId = Guid.NewGuid(),
            ProjectId = Guid.NewGuid(),
            Flags = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8), 0),
            ProtectionLevel = (EProtectionLevel)(Random.Shared.Next(0, byte.MaxValue) + 1),
            OrderBy = (EOrderBy)Random.Shared.Next(1, 6),
            FilterTag = (byte)Random.Shared.Next(0, 256),
            Filter = RandomNumberGenerator.GetBytes(Random.Shared.Next(5, 200)),
            FilterOperation = (EFilterOperation)Random.Shared.Next(1, 7),
            Skip = (ushort)Random.Shared.Next(0, ushort.MaxValue),
            Count = (byte)Random.Shared.Next(0, byte.MaxValue)
        };

    [Fact]
    public void Write_Parse_Roundtrips_AllProperties()
    {
        var packet = CreateRandomQueryPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);

        var parsed = Assert.IsType<QueryPacket>(Packet.Parse(buffer));

        Assert.Equal(packet.RequestId, parsed.RequestId);
        Assert.Equal(packet.ProjectId, parsed.ProjectId);
        Assert.Equal(packet.Flags, parsed.Flags);
        Assert.Equal(packet.ProtectionLevel, parsed.ProtectionLevel);
        Assert.Equal(packet.OrderBy, parsed.OrderBy);
        Assert.Equal(packet.FilterTag, parsed.FilterTag);
        Assert.Equal(packet.Filter, parsed.Filter);
        Assert.Equal(packet.FilterOperation, parsed.FilterOperation);
        Assert.Equal(packet.Skip, parsed.Skip);
        Assert.Equal(packet.Count, parsed.Count);
    }

    [Fact]
    public void Parse_ExistingByteArray_WriteBack_EqualsOriginal()
    {
        var originalPacket = CreateRandomQueryPacket();
        var originalBytes = originalPacket.ToByteArray();

        var parsed = Assert.IsType<QueryPacket>(Packet.Parse(originalBytes));

        var reserialized = parsed.ToByteArray();

        Assert.Equal(originalBytes, reserialized);
    }

    [Fact]
    public void Length_EncodedLength_MatchesPacketLength()
    {
        var packet = CreateRandomQueryPacket();

        var buffer = new byte[packet.Length()];
        packet.Write(buffer);
        Assert.Equal(packet.Length(), buffer.Length);

        var encodedLength = (buffer[2] << 8) | buffer[3];
        Assert.Equal(packet.Length() - 4, encodedLength);
    }
}
