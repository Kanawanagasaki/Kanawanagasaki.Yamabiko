namespace Kanawanagasaki.Yamabiko.Test.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class SupportedGroupsExtension_Tests
{
    [Fact]
    public void Length_ReturnsExpected()
    {
        var groups = new[] { ENamedGroup.SECP256R1, ENamedGroup.X25519 };
        var ext = new SupportedGroupsExtension(groups);

        // 2 bytes for length + 2 bytes per group
        Assert.Equal(2 + groups.Length * 2, ext.Length(true));
    }

    [Fact]
    public void Write_WritesCorrectBytes()
    {
        var groups = new[] { ENamedGroup.SECP256R1, ENamedGroup.X25519 };
        var ext = new SupportedGroupsExtension(groups);

        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        // first two bytes: data length = 4 (0x0004)
        Assert.Equal((byte)0x00, buffer[0]);
        Assert.Equal((byte)0x04, buffer[1]);

        // payload: 0x00 0x17 0x00 0x1D
        Assert.Equal((byte)0x00, buffer[2]);
        Assert.Equal((byte)0x17, buffer[3]);
        Assert.Equal((byte)0x00, buffer[4]);
        Assert.Equal((byte)0x1D, buffer[5]);
    }

    [Fact]
    public void Write_BufferTooSmall_ThrowsArgumentException()
    {
        var groups = new[] { ENamedGroup.SECP256R1, ENamedGroup.X25519 };
        var ext = new SupportedGroupsExtension(groups);

        var buffer = new byte[ext.Length(true) - 1]; // intentionally too small
        Assert.Throws<ArgumentException>(() => ext.Write(buffer, true));
    }

    [Fact]
    public void Parse_ReadsGroupsSuccessfully()
    {
        // build buffer for two groups: 0x0017, 0x001D
        var payloadLen = 4;
        var buffer = new byte[2 + payloadLen];
        buffer[0] = (byte)(payloadLen >> 8);
        buffer[1] = (byte)(payloadLen & 0xFF);

        // 0x00 0x17
        buffer[2] = 0x00;
        buffer[3] = 0x17;

        // 0x00 0x1D
        buffer[4] = 0x00;
        buffer[5] = 0x1D;

        var ext = SupportedGroupsExtension.Parse(buffer, true);

        Assert.Equal(2, ext.Groups.Length);
        Assert.Equal(ENamedGroup.SECP256R1, ext.Groups[0]);
        Assert.Equal(ENamedGroup.X25519, ext.Groups[1]);
    }

    [Fact]
    public void Parse_MalformedLength_ThrowsFormatException_WhenLengthExceedsBuffer()
    {
        // declare len = 4 but provide only 3 bytes of data -> dataEnd > buffer.Length
        var declaredLen = 4;
        var buffer = new byte[2 + 3]; // too short
        buffer[0] = (byte)(declaredLen >> 8);
        buffer[1] = (byte)(declaredLen & 0xFF);

        Assert.Throws<FormatException>(() => SupportedGroupsExtension.Parse(buffer, true));
    }

    [Fact]
    public void Parse_OddLength_ThrowsFormatException()
    {
        // declare an odd length (3)
        var declaredLen = 3;
        var buffer = new byte[2 + declaredLen];
        buffer[0] = (byte)(declaredLen >> 8);
        buffer[1] = (byte)(declaredLen & 0xFF);

        // fill with arbitrary bytes
        buffer[2] = 0x01;
        buffer[3] = 0x02;
        buffer[4] = 0x03;

        var ex = Assert.Throws<FormatException>(() => SupportedGroupsExtension.Parse(buffer, true));
        Assert.Contains("must be even", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_NoGroups_ThrowsFormatException()
    {
        // length = 0 -> no groups
        var buffer = new byte[2];
        buffer[0] = 0x00;
        buffer[1] = 0x00;

        var ex = Assert.Throws<FormatException>(() => SupportedGroupsExtension.Parse(buffer, true));
        Assert.Contains("At least one named group", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_UnknownGroup_ThrowsFormatException()
    {
        // length = 2, group value = 0x9999 (not defined)
        var declaredLen = 2;
        var buffer = new byte[2 + declaredLen];
        buffer[0] = (byte)(declaredLen >> 8);
        buffer[1] = (byte)(declaredLen & 0xFF);

        buffer[2] = 0x99;
        buffer[3] = 0x99;

        var ex = Assert.Throws<FormatException>(() => SupportedGroupsExtension.Parse(buffer, true));
        Assert.Contains("Unsupported or invalid named group", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RoundTrip_WriteThenParse_ReturnsSameGroups()
    {
        var original = new[] { ENamedGroup.SECP256R1, ENamedGroup.X25519 };
        var ext = new SupportedGroupsExtension(original);

        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        var parsed = SupportedGroupsExtension.Parse(buffer, true);

        Assert.Equal(original.Length, parsed.Groups.Length);
        Assert.True(original.SequenceEqual(parsed.Groups));
    }

    [Fact]
    public void Write_LargeGroupList_ThrowsFormatException_WhenDataLengthExceedsUShort()
    {
        // Create an array longer than 32767 -> len = Groups.Length * 2 = 65536 > ushort.MaxValue (65535)
        // This should trigger the FormatException path in Write().
        const int hugeCount = 32768; // 32768 * 2 = 65536
        var hugeGroups = Enumerable.Repeat(ENamedGroup.SECP256R1, hugeCount).ToArray();
        var ext = new SupportedGroupsExtension(hugeGroups);

        // Allocate a buffer large enough so the Write method doesn't immediately fail on buffer size.
        var buffer = new byte[ext.Length(true)];

        var ex = Assert.Throws<FormatException>(() => ext.Write(buffer, true));
        Assert.Contains("exceeds", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
