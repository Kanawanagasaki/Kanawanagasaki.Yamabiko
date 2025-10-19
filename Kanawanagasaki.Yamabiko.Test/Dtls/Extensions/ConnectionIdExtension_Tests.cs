namespace Kanawanagasaki.Yamabiko.Test.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class ConnectionIdExtension_Tests
{
    private static readonly Guid FixedGuid = new Guid("00112233-4455-6677-8899-aabbccddeeff");

    [Fact]
    public void Write_UsingRfc4122GuidBytes_WireMatchesRfc4122()
    {
        var rfcBytes = FixedGuid.ToByteArray(true);
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
        var rfcBytes = FixedGuid.ToByteArray(true);

        var data = new byte[1 + rfcBytes.Length];
        data[0] = (byte)rfcBytes.Length;
        Array.Copy(rfcBytes, 0, data, 1, rfcBytes.Length);

        var ext = ConnectionIdExtension.Parse(data, true);

        Assert.Equal(rfcBytes, ext.ConnectionId);

        var guid = new Guid(ext.ConnectionId, true);
        Assert.Equal(FixedGuid, guid);
    }

    [Fact]
    public void RoundTrip_WithGuid_ConvertsProperly()
    {
        var rfcBytes = FixedGuid.ToByteArray(true);
        var extOut = new ConnectionIdExtension(rfcBytes);

        var buf = new byte[extOut.Length(true)];
        extOut.Write(buf, true);

        var parsed = ConnectionIdExtension.Parse(buf, true);

        Assert.Equal(rfcBytes, parsed.ConnectionId);

        var guid = new Guid(parsed.ConnectionId, true);
        Assert.Equal(FixedGuid, guid);
    }
}
