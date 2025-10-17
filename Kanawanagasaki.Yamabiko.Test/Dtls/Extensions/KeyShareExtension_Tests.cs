namespace Kanawanagasaki.Yamabiko.Test.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class KeyShareExtension_Tests
{
    private static byte[] PatternBytes(int length)
    {
        var b = new byte[length];
        for (int i = 0; i < length; i++)
            b[i] = (byte)(i & 0xFF);
        return b;
    }

    [Fact]
    public void Length_SingleEntry_IsCorrect()
    {
        var key = PatternBytes(32);
        var dict = new Dictionary<ENamedGroup, byte[]> { { ENamedGroup.X25519, key } };
        var ext = new KeyShareExtension(dict);

        // 2 bytes length + (2 bytes group + 2 bytes key length + key bytes)
        int expected = 2 + (2 + 2 + key.Length);
        Assert.Equal(expected, ext.Length(true));
    }

    [Fact]
    public void WriteAndParse_Roundtrip_SingleEntry()
    {
        var key = PatternBytes(32);
        var dict = new Dictionary<ENamedGroup, byte[]> { { ENamedGroup.X25519, key } };
        var ext = new KeyShareExtension(dict);

        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        var parsed = KeyShareExtension.Parse(buffer.AsSpan(), true);

        Assert.Single(parsed.GroupToKey);
        Assert.True(parsed.GroupToKey.ContainsKey(ENamedGroup.X25519));
        Assert.Equal(key, parsed.GroupToKey[ENamedGroup.X25519]);
    }

    [Fact]
    public void WriteAndParse_Roundtrip_MultipleEntries()
    {
        var k1 = PatternBytes(32);
        var k2 = PatternBytes(65);
        var dict = new Dictionary<ENamedGroup, byte[]>
        {
            { ENamedGroup.SECP256R1, k1 },
            { ENamedGroup.X25519, k2 }
        };

        var ext = new KeyShareExtension(dict);
        var buffer = new byte[ext.Length(true)];
        ext.Write(buffer, true);

        var parsed = KeyShareExtension.Parse(buffer.AsSpan(), true);

        Assert.Equal(2, parsed.GroupToKey.Count);
        Assert.Equal(k1, parsed.GroupToKey[ENamedGroup.SECP256R1]);
        Assert.Equal(k2, parsed.GroupToKey[ENamedGroup.X25519]);
    }

    [Fact]
    public void Write_BufferTooSmall_ThrowsArgumentException()
    {
        var key = PatternBytes(32);
        var dict = new Dictionary<ENamedGroup, byte[]> { { ENamedGroup.X25519, key } };
        var ext = new KeyShareExtension(dict);

        var buffer = new byte[ext.Length(true) - 1];
        Assert.Throws<ArgumentException>(() => ext.Write(buffer, true));
    }

    [Fact]
    public void Parse_BufferTooSmallToReadLength_ThrowsFormatException()
    {
        var tiny = new byte[1];
        Assert.Throws<FormatException>(() => KeyShareExtension.Parse(tiny.AsSpan(), true));
    }

    [Fact]
    public void Parse_ExtensionLengthExceedsAvailable_ThrowsFormatException()
    {
        // Declared length 10 but only 1 byte of data present
        var buf = new byte[] { 0x00, 0x0A, 0x01 };
        Assert.Throws<FormatException>(() => KeyShareExtension.Parse(buf.AsSpan(), true));
    }

    [Fact]
    public void Parse_InsufficientDataForGroupAndKeyLength_ThrowsFormatException()
    {
        // Declared length 3 (less than required 4 for group+keylen)
        var buf = new byte[] { 0x00, 0x03, 0x01, 0x02, 0x03 };
        Assert.Throws<FormatException>(() => KeyShareExtension.Parse(buf.AsSpan(), true));
    }

    [Fact]
    public void Parse_KeyLengthExceedsAvailable_ThrowsFormatException()
    {
        // Header: length = 6, then group (2 bytes) + keylen (2 bytes=5) but only 1 byte of key provided
        var list = new List<byte>
        {
            0x00, 0x06, // total extension length
            0x00, 0x1D, // group = X25519
            0x00, 0x05, // key length = 5
            0x01 // only 1 byte of key
        };
        var buf = list.ToArray();

        Assert.Throws<FormatException>(() => KeyShareExtension.Parse(buf.AsSpan(), true));
    }

    [Fact]
    public void Parse_ZeroLengthKey_IsIgnored()
    {
        // length = 4 (group + keylen), keylen = 0 -> group should not be present in dict
        var buf = new byte[] {
            0x00, 0x04, // len
            0x00, 0x1D, // group X25519
            0x00, 0x00  // keylen 0
        };

        var parsed = KeyShareExtension.Parse(buf.AsSpan(), true);
        Assert.Empty(parsed.GroupToKey);
    }

    [Fact]
    public void Write_TotalLengthExceedsUShort_ThrowsFormatException()
    {
        // Create a single huge key that causes the total inner length to exceed ushort.MaxValue
        var huge = new byte[65535]; // key length 65535
        var dict = new Dictionary<ENamedGroup, byte[]> { { ENamedGroup.X25519, huge } };
        var ext = new KeyShareExtension(dict);

        // total len = 4 + 65535 = 65539 > 65535 -> should throw in Write
        Assert.Throws<FormatException>(() =>
        {
            var buffer = new byte[ext.Length(true)]; // we don't actually expect to reach here safely, but keep it defensive
            ext.Write(buffer, true);
        });
    }
}
