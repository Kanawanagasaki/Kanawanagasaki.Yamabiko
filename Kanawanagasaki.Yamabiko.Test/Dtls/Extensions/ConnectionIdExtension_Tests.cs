namespace Kanawanagasaki.Yamabiko.Test.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class ConnectionIdExtension_Tests
{
    private static readonly Guid FixedGuid = new Guid("00112233-4455-6677-8899-aabbccddeeff");

    [Fact]
    public void Write_UsingRfc4122GuidBytes_WireMatchesRfc4122()
    {
        var rfcBytes = GuidToRfc4122Bytes(FixedGuid);
        var extension = new ConnectionIdExtension(rfcBytes);

        var length = extension.Length(true);
        Assert.Equal(1 + rfcBytes.Length, length);

        var buffer = new byte[length];
        extension.Write(buffer, true);

        Assert.Equal((byte)rfcBytes.Length, buffer[0]);
        Assert.Equal(rfcBytes, buffer[1..]);
    }

    [Fact]
    public void Parse_WireRfc4122Bytes_CanConvertBackToGuid()
    {
        var rfcBytes = GuidToRfc4122Bytes(FixedGuid);

        var data = new byte[1 + rfcBytes.Length];
        data[0] = (byte)rfcBytes.Length;
        Array.Copy(rfcBytes, 0, data, 1, rfcBytes.Length);

        var ext = ConnectionIdExtension.Parse(data, true);

        Assert.Equal(rfcBytes, ext.ConnectionId);

        var guid = Rfc4122BytesToGuid(ext.ConnectionId);
        Assert.Equal(FixedGuid, guid);
    }

    [Fact]
    public void RoundTrip_WithGuid_ConvertsProperly()
    {
        var rfcBytes = GuidToRfc4122Bytes(FixedGuid);
        var extOut = new ConnectionIdExtension(rfcBytes);

        var buf = new byte[extOut.Length(true)];
        extOut.Write(buf, true);

        var parsed = ConnectionIdExtension.Parse(buf, true);

        Assert.Equal(rfcBytes, parsed.ConnectionId);

        var guid = Rfc4122BytesToGuid(parsed.ConnectionId);
        Assert.Equal(FixedGuid, guid);
    }

    public static byte[] GuidToRfc4122Bytes(Guid g)
    {
        var b = g.ToByteArray();
        return
        [
            b[3], b[2], b[1], b[0],
            b[5], b[4],
            b[7], b[6],
            b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        ];
    }

    public static Guid Rfc4122BytesToGuid(ReadOnlySpan<byte> netBytes)
    {
        if (netBytes.Length != 16)
            throw new ArgumentException("RFC4122 UUID must be 16 bytes", nameof(netBytes));

        var b = new byte[16];
        b[0] = netBytes[3];
        b[1] = netBytes[2];
        b[2] = netBytes[1];
        b[3] = netBytes[0];
        b[4] = netBytes[5];
        b[5] = netBytes[4];
        b[6] = netBytes[7];
        b[7] = netBytes[6];

        for (int i = 8; i < 16; i++)
            b[i] = netBytes[i];

        return new Guid(b);
    }
}
