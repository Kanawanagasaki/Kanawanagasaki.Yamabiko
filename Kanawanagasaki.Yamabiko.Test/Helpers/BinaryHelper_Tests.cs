namespace Kanawanagasaki.Yamabiko.Test.Helpers;

using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using Kanawanagasaki.Yamabiko.Shared;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System.Collections;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Xunit.Abstractions;

public class BinaryHelper_Tests(ITestOutputHelper _output)
{
    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(123)]
    [InlineData(-321)]
    [InlineData(short.MaxValue)]
    [InlineData(short.MinValue)]
    public void Int16_Roundtrip(short value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(2, o);

        int readOff = 0;
        var read = BinaryHelper.ReadInt16(buffer, ref readOff);
        Assert.Equal(value, read);
        Assert.Equal(2, readOff);
    }


    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(123)]
    [InlineData(321)]
    [InlineData(ushort.MaxValue)]
    public void UInt16_Roundtrip(ushort value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(2, o);

        int readOff = 0;
        var read = BinaryHelper.ReadUInt16(buffer, ref readOff);
        Assert.Equal(value, read);
        Assert.Equal(2, readOff);
    }


    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(-0xFFFF)]
    [InlineData(0x123123)]
    [InlineData(int.MaxValue)]
    [InlineData(int.MinValue)]
    public void Int32_Roundtrip(int value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(4, o);

        int readOff = 0;
        var read = BinaryHelper.ReadInt32(buffer, ref readOff);
        Assert.Equal(value, read);
        Assert.Equal(4, readOff);
    }


    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(0xFFFF)]
    [InlineData(0x123123)]
    [InlineData(uint.MaxValue)]
    public void UInt32_Roundtrip(uint value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(4, o);

        int readOff = 0;
        var read = BinaryHelper.ReadUInt32(buffer, ref readOff);
        Assert.Equal(value, read);
        Assert.Equal(4, readOff);
    }


    [Theory]
    [InlineData(0L)]
    [InlineData(1L)]
    [InlineData(-1L)]
    [InlineData(0x1122334455667788)]
    [InlineData(-0x1122334455667788)]
    [InlineData(long.MaxValue)]
    [InlineData(long.MinValue)]
    public void Int64_Roundtrip(long value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(8, o);

        int readOff = 0;
        var read = BinaryHelper.ReadInt64(buffer, ref readOff);
        Assert.Equal(value, read);
        Assert.Equal(8, readOff);
    }


    [Theory]
    [InlineData(0)]
    [InlineData(1)]
    [InlineData(0x1122334455667788LU)]
    [InlineData(0xFEDCBA9876543210LU)]
    [InlineData(ulong.MaxValue)]
    public void UInt64_Roundtrip(ulong value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(8, o);

        int readOff = 0;
        var read = BinaryHelper.ReadUInt64(buffer, ref readOff);
        Assert.Equal(value, read);
        Assert.Equal(8, readOff);
    }


    public static IEnumerable<object[]> FloatRoundtripData()
    {
        yield return new object[] { float.NegativeInfinity };
        yield return new object[] { -34.32f };
        yield return new object[] { -5f };
        yield return new object[] { BitConverter.Int32BitsToSingle(unchecked((int)0x80000000)) };
        yield return new object[] { 0f };
        yield return new object[] { 545f };
        yield return new object[] { 1010.232f };
        yield return new object[] { float.PositiveInfinity };
        yield return new object[] { float.NaN };
    }

    [Theory]
    [MemberData(nameof(FloatRoundtripData))]
    public void Single_Roundtrip(float value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(4, o);

        int readOff = 0;
        var read = BinaryHelper.ReadSingle(buffer, ref readOff);

        var expectedBits = BitConverter.SingleToInt32Bits(value);
        var actualBits = BitConverter.SingleToInt32Bits(read);
        if (float.IsNaN(value))
        {
            Assert.True(float.IsNaN(read));
            Assert.Equal(expectedBits, actualBits);
        }
        else
        {
            Assert.Equal(expectedBits, actualBits);
        }
    }

    [Fact]
    public void Single_EncodedBytes_AreLexicographicallySortable()
    {
        var values = new float[]
        {
            float.NegativeInfinity,
            -34.32f,
            -5f,
            BitConverter.Int32BitsToSingle(unchecked((int)0x80000000)),
            0f,
            545f,
            1010.232f,
            float.PositiveInfinity,
            float.NaN
        };

        Array.Sort(values);

        var byteArrays = new byte[values.Length][];
        foreach (var (index, value) in values.OrderBy(_ => Random.Shared.NextDouble()).Index())
        {
            int o = 0;
            byteArrays[index] = new byte[BinaryHelper.BytesCount(value)];
            BinaryHelper.Write(value, byteArrays[index], ref o);
        }

        Array.Sort(byteArrays, KeyHashHelper.CompareByteArrayLex);

        for (int i = 0; i < byteArrays.Length; i++)
        {
            int o = 0;
            var val = BinaryHelper.ReadSingle(byteArrays[i], ref o);
            Assert.Equal(values[i], val);
        }
    }

    public static IEnumerable<object[]> DoubleRoundtripData()
    {
        yield return new object[] { double.NegativeInfinity };
        yield return new object[] { -34.32 };
        yield return new object[] { -5.0 };
        yield return new object[] { BitConverter.Int64BitsToDouble(unchecked((long)0x8000000000000000L)) };
        yield return new object[] { 0.0 };
        yield return new object[] { 545.0 };
        yield return new object[] { 1010.232 };
        yield return new object[] { double.PositiveInfinity };
        yield return new object[] { double.NaN };
    }

    [Theory]
    [MemberData(nameof(DoubleRoundtripData))]
    public void Double_Roundtrip(double value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(value, buffer, ref o);
        Assert.Equal(8, o);

        int readOff = 0;
        var read = BinaryHelper.ReadDouble(buffer, ref readOff);
        var expectedBits = BitConverter.DoubleToInt64Bits(value);
        var actualBits = BitConverter.DoubleToInt64Bits(read);

        if (double.IsNaN(value))
        {
            Assert.True(double.IsNaN(read));
            Assert.Equal(expectedBits, actualBits);
        }
        else
        {
            Assert.Equal(expectedBits, actualBits);
        }
    }

    [Fact]
    public void Double_EncodedBytes_AreLexicographicallySortable()
    {
        var values = new double[]
        {
            double.NegativeInfinity,
            -34.32,
            -5.0,
            BitConverter.Int64BitsToDouble(unchecked((long)0x8000000000000000L)),
            0.0,
            545.0,
            1010.232,
            double.PositiveInfinity,
            double.NaN
        };

        Array.Sort(values);

        var byteArrays = new byte[values.Length][];
        foreach (var (index, value) in values.OrderBy(_ => Random.Shared.NextDouble()).Index())
        {
            int o = 0;
            byteArrays[index] = new byte[BinaryHelper.BytesCount(value)];
            BinaryHelper.Write(value, byteArrays[index], ref o);
        }

        Array.Sort(byteArrays, KeyHashHelper.CompareByteArrayLex);

        for (int i = 0; i < byteArrays.Length; i++)
        {
            int o = 0;
            var val = BinaryHelper.ReadDouble(byteArrays[i], ref o);
            Assert.Equal(values[i], val);
        }
    }

    [Theory]
    [InlineData("00000000-0000-0000-0000-000000000000")]
    [InlineData("01234567-89ab-cdef-0123-456789abcdef")]
    public void Guid_Roundtrip(string guidText)
    {
        var guid = Guid.Parse(guidText);
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(guid, buffer, ref o);
        Assert.Equal(16, o);

        int readOff = 0;
        var read = BinaryHelper.ReadGuid(buffer, ref readOff);
        Assert.Equal(guid, read);
        Assert.Equal(16, readOff);
    }


    public static IEnumerable<object[]> IPAddressRoundtripData()
    {
        yield return new object[] { new IPAddress(RandomNumberGenerator.GetBytes(4)) };
        yield return new object[] { new IPAddress(RandomNumberGenerator.GetBytes(16)) };
        yield return new object[] { IPAddress.Parse("127.0.0.1") };
        yield return new object[] { IPAddress.Parse("192.168.1.100") };
        yield return new object[] { IPAddress.Parse("::1") };
        yield return new object[] { IPAddress.Parse("2001:0db8:85a3::8a2e:0370:7334") };
    }

    [Theory]
    [MemberData(nameof(IPAddressRoundtripData))]
    public void IPAddress_Roundtrip(IPAddress ip)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(ip, buffer, ref o);

        int readOff = 0;
        var read = BinaryHelper.ReadIPAddress(buffer, ref readOff);
        Assert.Equal(ip, read);
    }

    [Fact]
    public void IPAddress_Roundtrip_Multiple()
    {
        var arr = new IPAddress[Random.Shared.Next(5, 20)];
        for (int i = 0; i < arr.Length; i++)
            arr[i] = new IPAddress(RandomNumberGenerator.GetBytes(Random.Shared.NextDouble() < 0.5 ? 4 : 16));

        var buffer = new byte[1000];
        int o = 0;

        foreach (var ip in arr)
            BinaryHelper.Write(ip, buffer, ref o);

        int readOff = 0;
        int index = 0;
        while (readOff < o)
        {
            var ip = BinaryHelper.ReadIPAddress(buffer, ref readOff);
            Assert.Equal(arr[index], ip);
            index++;
        }

        Assert.Equal(arr.Length, index);
    }

    public static IEnumerable<object[]> VarIntRoundtripData()
    {
        yield return new object[] { 0L };
        yield return new object[] { -1L };
        yield return new object[] { 1L };
        yield return new object[] { -2L };
        yield return new object[] { 127L };
        yield return new object[] { 128L };
        yield return new object[] { 255L };
        yield return new object[] { 256L };
        yield return new object[] { 300L };
        yield return new object[] { -300L };
        yield return new object[] { 123456789L };
        yield return new object[] { -123456789L };
        yield return new object[] { long.MaxValue };
        yield return new object[] { long.MinValue };
    }

    [Theory]
    [MemberData(nameof(VarIntRoundtripData))]
    public void VarInt_Roundtrip(long value)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write((VarInt)value, buffer, ref o);
        var len = o;

        int readOff = 0;
        var read = BinaryHelper.ReadVarInt(buffer, ref readOff);
        Assert.Equal(len, readOff);


        Assert.Equal(value, (long)read);

        _output.WriteLine(string.Join(", ", buffer[0..o]));
    }

    [Fact]
    public void VarInt_Roundtrip_Random()
    {
        for (int i = 0; i < 100; i++)
        {
            var value = Random.Shared.NextInt64(long.MinValue, long.MaxValue);

            var buffer = new byte[100];
            int o = 0;
            BinaryHelper.Write((VarInt)value, buffer, ref o);
            var len = o;

            int readOff = 0;
            var read = BinaryHelper.ReadVarInt(buffer, ref readOff);
            Assert.Equal(len, readOff);


            Assert.Equal(value, (long)read);
        }
    }

    [Theory]
    [InlineData(0L, new byte[] { 0x00 })]
    [InlineData(-1L, new byte[] { 0x01 })]
    [InlineData(1L, new byte[] { 0x02 })]
    [InlineData(-2L, new byte[] { 0x03 })]
    [InlineData(127L, new byte[] { 0x81, 0x7E })]
    [InlineData(128L, new byte[] { 0x82, 0x00 })]
    [InlineData(255L, new byte[] { 0x83, 0x7E })]
    [InlineData(256L, new byte[] { 0x84, 0x00 })]
    [InlineData(300L, new byte[] { 0x84, 0x58 })]
    [InlineData(-300L, new byte[] { 0x84, 0x57 })]
    [InlineData(123456789L, new byte[] { 0xF5, 0xDE, 0xB4, 0x2A })]
    [InlineData(-123456789L, new byte[] { 0xF5, 0xDE, 0xB4, 0x29 })]
    [InlineData(9223372036854775807L, new byte[] { 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7E })]
    [InlineData(-9223372036854775808L, new byte[] { 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F })]
    public void VarInt_EncodesToExpectedBytes(long value, byte[] expected)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write((VarInt)value, buffer, ref o);
        var actual = new byte[o];
        Array.Copy(buffer, 0, actual, 0, o);
        Assert.Equal(expected, actual);
    }

    [Fact]
    public void ByteArray_Roundtrip_Random()
    {
        byte[]? byteArray = Random.Shared.NextDouble() < 0.75 ? RandomNumberGenerator.GetBytes(Random.Shared.Next(100, 1000)) : null;
        var buffer = new byte[2000];
        int o = 0;
        BinaryHelper.Write(byteArray, buffer, ref o);

        int readOffset = 0;
        var read = BinaryHelper.ReadByteArray(buffer, ref readOffset); ;

        Assert.Equal(o, readOffset);
        Assert.Equal(byteArray, read);
    }

    [Fact]
    public void ByteArray_Roundtrip_Random_Multiple()
    {
        byte[]?[] byteArrays = new byte[Random.Shared.Next(5, 20)][];
        for (int i = 0; i < byteArrays.Length; i++)
            byteArrays[i] = Random.Shared.NextDouble() < 0.75 ? RandomNumberGenerator.GetBytes(Random.Shared.Next(100, 1000)) : null;

        var buffer = new byte[40000];
        int o = 0;
        foreach (var byteArray in byteArrays)
            BinaryHelper.Write(byteArray, buffer, ref o);

        int readOffset = 0;
        int index = 0;
        while (readOffset < o)
        {
            var byteArray = BinaryHelper.ReadByteArray(buffer, ref readOffset);
            Assert.Equal(byteArrays[index], byteArray);
            index++;
        }

        Assert.Equal(o, readOffset);
        Assert.Equal(byteArrays.Length, index);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("Hello, world!")]
    [InlineData("Blalalalalalallalalalalala")]
    [InlineData("\x0\x1\x2\x3\x4\x5\x6\x7\x8\x9\xa\xb\xc\xd\xe\xf")]
    public void String_Roundtrip(string? str)
    {
        var buffer = new byte[100];
        int o = 0;
        BinaryHelper.Write(str, buffer, ref o);

        int readOffset = 0;
        var readStr = BinaryHelper.ReadString(buffer, ref readOffset);

        Assert.Equal(o, readOffset);
        Assert.Equal(str, readStr);
    }

    [Fact]
    public void String_Roundtrip_Random()
    {
        var str = Encoding.UTF8.GetString(RandomNumberGenerator.GetBytes(Random.Shared.Next(100, 1000)));
        var buffer = new byte[2000];
        int o = 0;
        BinaryHelper.Write(str, buffer, ref o);

        int readOffset = 0;
        var readStr = BinaryHelper.ReadString(buffer, ref readOffset);

        Assert.Equal(o, readOffset);
        Assert.Equal(str, readStr);
    }

    [Fact]
    public void String_Roundtrip_Random_Multiple()
    {
        var arr = new string?[Random.Shared.Next(5, 50)];
        for (int i = 0; i < arr.Length; i++)
        {
            if (Random.Shared.NextDouble() < 0.75)
                arr[i] = Encoding.UTF8.GetString(RandomNumberGenerator.GetBytes(Random.Shared.Next(5, 20)));
            else
                arr[i] = null;
        }

        var buffer = new byte[20000];
        int o = 0;

        foreach (var str in arr)
            BinaryHelper.Write(str, buffer, ref o);

        int readOffset = 0;
        int index = 0;
        while (readOffset < o)
        {
            var readStr = BinaryHelper.ReadString(buffer, ref readOffset);
            Assert.Equal(arr[index], readStr);
            index++;
        }

        Assert.Equal(o, readOffset);
    }
}
