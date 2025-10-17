namespace Kanawanagasaki.Yamabiko.Test.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class SupportedVersionsExtension_Tests
{
    [Fact]
    public void Length_ReturnsExpected()
    {
        var versions = new[] { EVersions.DTLS1_2, EVersions.DTLS1_3 };
        var ext = new SupportedVersionsExtension(versions);

        // 1 byte for length + 2 bytes per version
        Assert.Equal(1 + versions.Length * 2, ext.Length(true));
    }

    [Fact]
    public void Write_WritesCorrectBytes()
    {
        var versions = new[] { EVersions.DTLS1_2, EVersions.DTLS1_3 }; // 0xFEFD, 0xFEFC
        var ext = new SupportedVersionsExtension(versions);

        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        // first byte: data length = 4 (0x04)
        Assert.Equal((byte)0x04, buffer[0]);

        // payload: 0xFE 0xFD  0xFE 0xFC
        Assert.Equal((byte)0xFE, buffer[1]);
        Assert.Equal((byte)0xFD, buffer[2]);
        Assert.Equal((byte)0xFE, buffer[3]);
        Assert.Equal((byte)0xFC, buffer[4]);
    }

    [Fact]
    public void Write_BufferTooSmall_ThrowsArgumentException()
    {
        var versions = new[] { EVersions.DTLS1_2, EVersions.DTLS1_3 };
        var ext = new SupportedVersionsExtension(versions);

        var buffer = new byte[ext.Length(true) - 1]; // intentionally too small
        Assert.Throws<ArgumentException>(() => ext.Write(buffer, true));
    }

    [Fact]
    public void Parse_ReadsVersionsSuccessfully()
    {
        // build buffer for two versions: 0xFEFD, 0xFEFC
        var payloadLen = 4;
        var buffer = new byte[1 + payloadLen];
        buffer[0] = (byte)payloadLen;

        // 0xFE 0xFD
        buffer[1] = 0xFE;
        buffer[2] = 0xFD;

        // 0xFE 0xFC
        buffer[3] = 0xFE;
        buffer[4] = 0xFC;

        var ext = SupportedVersionsExtension.Parse(buffer, true);

        Assert.Equal(2, ext.Versions.Length);
        Assert.Equal(EVersions.DTLS1_2, ext.Versions[0]);
        Assert.Equal(EVersions.DTLS1_3, ext.Versions[1]);
    }

    [Fact]
    public void Parse_MalformedLength_ThrowsFormatException_WhenLengthExceedsBuffer()
    {
        // declare len = 4 but provide only 3 bytes of data -> dataEnd > buffer.Length
        var declaredLen = 4;
        var buffer = new byte[1 + 3]; // too short
        buffer[0] = (byte)declaredLen;

        Assert.Throws<FormatException>(() => SupportedVersionsExtension.Parse(buffer, true));
    }

    [Fact]
    public void Parse_OddLength_ThrowsFormatException()
    {
        // declare an odd length (3)
        var declaredLen = 3;
        var buffer = new byte[1 + declaredLen];
        buffer[0] = (byte)declaredLen;

        // fill with arbitrary bytes
        buffer[1] = 0x01;
        buffer[2] = 0x02;
        buffer[3] = 0x03;

        var ex = Assert.Throws<FormatException>(() => SupportedVersionsExtension.Parse(buffer, true));
        Assert.Contains("must be even", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_NoVersions_ThrowsFormatException()
    {
        // length = 0 -> no versions
        var buffer = new byte[1];
        buffer[0] = 0x00;

        var ex = Assert.Throws<FormatException>(() => SupportedVersionsExtension.Parse(buffer, true));
        Assert.Contains("At least version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_UnknownVersion_ThrowsFormatException()
    {
        // length = 2, version value = 0x9999 (not defined)
        var declaredLen = 2;
        var buffer = new byte[1 + declaredLen];
        buffer[0] = (byte)declaredLen;

        buffer[1] = 0x99;
        buffer[2] = 0x99;

        var ex = Assert.Throws<FormatException>(() => SupportedVersionsExtension.Parse(buffer, true));
        Assert.Contains("Unsupported or invalid version", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RoundTrip_WriteThenParse_ReturnsSameVersions()
    {
        var original = new[] { EVersions.DTLS1_0, EVersions.DTLS1_2, EVersions.DTLS1_3 };
        var ext = new SupportedVersionsExtension(original);

        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        var parsed = SupportedVersionsExtension.Parse(buffer, true);

        Assert.Equal(original.Length, parsed.Versions.Length);
        Assert.True(original.SequenceEqual(parsed.Versions));
    }

    [Fact]
    public void Write_LargeVersionList_ThrowsFormatException_WhenDataLengthExceedsByte()
    {
        // Need Versions.Length * 2 > 255 to trigger the byte.MaxValue check.
        // Versions.Length = 128 -> 128*2 = 256 > 255
        const int hugeCount = 128;
        var hugeVersions = Enumerable.Repeat(EVersions.DTLS1_2, hugeCount).ToArray();
        var ext = new SupportedVersionsExtension(hugeVersions);

        // Allocate a buffer equal to Length so the initial buffer-size check passes.
        var buffer = new byte[ext.Length(true)];

        var ex = Assert.Throws<FormatException>(() => ext.Write(buffer, true));
        Assert.Contains("exceeds", ex.Message, StringComparison.OrdinalIgnoreCase);
    }
}
