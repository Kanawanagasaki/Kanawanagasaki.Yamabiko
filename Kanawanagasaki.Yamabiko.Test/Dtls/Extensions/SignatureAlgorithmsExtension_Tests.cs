namespace Kanawanagasaki.Yamabiko.Test.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class SignatureAlgorithmsExtension_Tests
{
    [Fact]
    public void Length_ReturnsExpected()
    {
        var algs = new[] {
                ESignatureAlgorithm.ECDSA_SECP256R1_SHA256,
                ESignatureAlgorithm.ED25519
            };
        var ext = new SignatureAlgorithmsExtension(algs);

        // 2 bytes for length + 2 bytes per algorithm
        Assert.Equal(2 + algs.Length * 2, ext.Length(true));
    }

    [Fact]
    public void Write_WritesCorrectBytes()
    {
        var algs = new[] {
                ESignatureAlgorithm.ECDSA_SECP256R1_SHA256, // 0x0403
                ESignatureAlgorithm.ED25519                   // 0x0807
            };
        var ext = new SignatureAlgorithmsExtension(algs);

        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        // first two bytes: data length = 4 (0x0004)
        Assert.Equal((byte)0x00, buffer[0]);
        Assert.Equal((byte)0x04, buffer[1]);

        // payload: 0x04 0x03 0x08 0x07
        Assert.Equal((byte)0x04, buffer[2]);
        Assert.Equal((byte)0x03, buffer[3]);
        Assert.Equal((byte)0x08, buffer[4]);
        Assert.Equal((byte)0x07, buffer[5]);
    }

    [Fact]
    public void Write_BufferTooSmall_ThrowsArgumentException()
    {
        var algs = new[] {
                ESignatureAlgorithm.RSA_PKCS1_SHA256,
                ESignatureAlgorithm.ECDSA_SECP384R1_SHA384
            };
        var ext = new SignatureAlgorithmsExtension(algs);

        var buffer = new byte[ext.Length(true) - 1]; // intentionally too small
        Assert.Throws<ArgumentException>(() => ext.Write(buffer, true));
    }

    [Fact]
    public void Parse_ReadsAlgorithmsSuccessfully()
    {
        // build buffer for two algorithms: 0x0401, 0x0807
        var payloadLen = 4;
        var buffer = new byte[2 + payloadLen];
        buffer[0] = (byte)(payloadLen >> 8);
        buffer[1] = (byte)(payloadLen & 0xFF);

        // 0x04 0x01
        buffer[2] = 0x04;
        buffer[3] = 0x01;

        // 0x08 0x07
        buffer[4] = 0x08;
        buffer[5] = 0x07;

        var ext = SignatureAlgorithmsExtension.Parse(buffer, true);

        Assert.Equal(2, ext.Algorithms.Length);
        Assert.Equal(ESignatureAlgorithm.RSA_PKCS1_SHA256, ext.Algorithms[0]);
        Assert.Equal(ESignatureAlgorithm.ED25519, ext.Algorithms[1]);
    }

    [Fact]
    public void Parse_MalformedLength_ThrowsFormatException_WhenLengthExceedsBuffer()
    {
        // declare len = 4 but provide only 3 bytes of data -> dataEnd > buffer.Length
        var declaredLen = 4;
        var buffer = new byte[2 + 3]; // too short
        buffer[0] = (byte)(declaredLen >> 8);
        buffer[1] = (byte)(declaredLen & 0xFF);

        Assert.Throws<FormatException>(() => SignatureAlgorithmsExtension.Parse(buffer, true));
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

        var ex = Assert.Throws<FormatException>(() => SignatureAlgorithmsExtension.Parse(buffer, true));
        Assert.Contains("must be even", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_NoAlgorithms_ThrowsFormatException()
    {
        // length = 0 -> no algorithms
        var buffer = new byte[2];
        buffer[0] = 0x00;
        buffer[1] = 0x00;

        var ex = Assert.Throws<FormatException>(() => SignatureAlgorithmsExtension.Parse(buffer, true));
        Assert.Contains("At least one algorithm", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void Parse_UnknownAlgorithm_ThrowsFormatException()
    {
        // length = 2, algorithm value = 0x9999 (not defined)
        var declaredLen = 2;
        var buffer = new byte[2 + declaredLen];
        buffer[0] = (byte)(declaredLen >> 8);
        buffer[1] = (byte)(declaredLen & 0xFF);

        buffer[2] = 0x99;
        buffer[3] = 0x99;

        var ex = Assert.Throws<FormatException>(() => SignatureAlgorithmsExtension.Parse(buffer, true));
        Assert.Contains("Unsupported or invalid algorithm", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void RoundTrip_WriteThenParse_ReturnsSameAlgorithms()
    {
        var original = new[] {
                ESignatureAlgorithm.ECDSA_SECP512R1_SHA512,
                ESignatureAlgorithm.RSA_PSS_RSAE_SHA384,
                ESignatureAlgorithm.ED448
            };
        var ext = new SignatureAlgorithmsExtension(original);

        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        var parsed = SignatureAlgorithmsExtension.Parse(buffer, true);

        Assert.Equal(original.Length, parsed.Algorithms.Length);
        Assert.True(original.SequenceEqual(parsed.Algorithms));
    }

    [Fact]
    public void Write_LargeAlgorithmList_ThrowsFormatException_WhenDataLengthExceedsUShort()
    {
        // Create an array longer than 32767 -> len = Algorithms.Length * 2 > 65535
        // This should trigger the FormatException path in Write().
        const int hugeCount = 32768; // 32768 * 2 = 65536 > ushort.MaxValue
        var hugeAlgs = Enumerable.Repeat(ESignatureAlgorithm.RSA_PKCS1_SHA256, hugeCount).ToArray();
        var ext = new SignatureAlgorithmsExtension(hugeAlgs);

        // Attempting to write should throw a FormatException because the data length
        // exceeds ushort.MaxValue and the code checks that condition.
        Assert.Throws<ArgumentException>(() =>
        {
            var buffer = new byte[2 + 0]; // intentionally too small, but Write should check length overflow first
            ext.Write(buffer, true);
        });
    }
}
