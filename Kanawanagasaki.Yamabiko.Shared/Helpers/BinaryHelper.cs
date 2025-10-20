namespace Kanawanagasaki.Yamabiko.Shared.Helpers;

using System.Net;
using System.Net.Sockets;
using System.Text;

public static class BinaryHelper
{
    public static short ReadInt16(ReadOnlySpan<byte> buffer, ref int offset)
        => (short)((buffer[offset++] << 8) | buffer[offset++]);
    public static void Write(short num, Span<byte> buffer, ref int offset)
    {
        buffer[offset++] = (byte)((num >> 8) & 0xFF);
        buffer[offset++] = (byte)(num & 0xFF);
    }
    public static int BytesCount(short _) => 2;



    public static ushort ReadUInt16(ReadOnlySpan<byte> buffer, ref int offset)
        => (ushort)((buffer[offset++] << 8) | buffer[offset++]);
    public static void Write(ushort num, Span<byte> buffer, ref int offset)
    {
        buffer[offset++] = (byte)((num >> 8) & 0xFF);
        buffer[offset++] = (byte)(num & 0xFF);
    }
    public static int BytesCount(ushort _) => 2;



    public static int ReadInt32(ReadOnlySpan<byte> buffer, ref int offset)
        => (buffer[offset++] << 24)
         | (buffer[offset++] << 16)
         | (buffer[offset++] << 8)
         | buffer[offset++];
    public static void Write(int num, Span<byte> buffer, ref int offset)
    {
        buffer[offset++] = (byte)((num >> 24) & 0xFF);
        buffer[offset++] = (byte)((num >> 16) & 0xFF);
        buffer[offset++] = (byte)((num >> 8) & 0xFF);
        buffer[offset++] = (byte)(num & 0xFF);
    }
    public static int BytesCount(int _) => 4;



    public static uint ReadUInt32(ReadOnlySpan<byte> buffer, ref int offset)
        => ((uint)buffer[offset++] << 24)
         | ((uint)buffer[offset++] << 16)
         | ((uint)buffer[offset++] << 8)
         | buffer[offset++];
    public static void Write(uint num, Span<byte> buffer, ref int offset)
    {
        buffer[offset++] = (byte)((num >> 24) & 0xFF);
        buffer[offset++] = (byte)((num >> 16) & 0xFF);
        buffer[offset++] = (byte)((num >> 8) & 0xFF);
        buffer[offset++] = (byte)(num & 0xFF);
    }
    public static int BytesCount(uint _) => 4;



    public static long ReadInt64(ReadOnlySpan<byte> buffer, ref int offset)
        => ((long)buffer[offset++] << 56)
         | ((long)buffer[offset++] << 48)
         | ((long)buffer[offset++] << 40)
         | ((long)buffer[offset++] << 32)
         | ((long)buffer[offset++] << 24)
         | ((long)buffer[offset++] << 16)
         | ((long)buffer[offset++] << 8)
         | buffer[offset++];
    public static void Write(long num, Span<byte> buffer, ref int offset)
    {
        buffer[offset++] = (byte)((num >> 56) & 0xFF);
        buffer[offset++] = (byte)((num >> 48) & 0xFF);
        buffer[offset++] = (byte)((num >> 40) & 0xFF);
        buffer[offset++] = (byte)((num >> 32) & 0xFF);
        buffer[offset++] = (byte)((num >> 24) & 0xFF);
        buffer[offset++] = (byte)((num >> 16) & 0xFF);
        buffer[offset++] = (byte)((num >> 8) & 0xFF);
        buffer[offset++] = (byte)(num & 0xFF);
    }
    public static int BytesCount(long _) => 8;



    public static ulong ReadUInt64(ReadOnlySpan<byte> buffer, ref int offset)
        => ((ulong)buffer[offset++] << 56)
         | ((ulong)buffer[offset++] << 48)
         | ((ulong)buffer[offset++] << 40)
         | ((ulong)buffer[offset++] << 32)
         | ((ulong)buffer[offset++] << 24)
         | ((ulong)buffer[offset++] << 16)
         | ((ulong)buffer[offset++] << 8)
         | buffer[offset++];
    public static void Write(ulong num, Span<byte> buffer, ref int offset)
    {
        buffer[offset++] = (byte)((num >> 56) & 0xFF);
        buffer[offset++] = (byte)((num >> 48) & 0xFF);
        buffer[offset++] = (byte)((num >> 40) & 0xFF);
        buffer[offset++] = (byte)((num >> 32) & 0xFF);
        buffer[offset++] = (byte)((num >> 24) & 0xFF);
        buffer[offset++] = (byte)((num >> 16) & 0xFF);
        buffer[offset++] = (byte)((num >> 8) & 0xFF);
        buffer[offset++] = (byte)(num & 0xFF);
    }
    public static int BytesCount(ulong _) => 8;



    public static float ReadSingle(ReadOnlySpan<byte> buffer, ref int offset)
    {
        const uint TOP_BIT = 0x8000_0000u;
        var transformed = ReadUInt32(buffer, ref offset);
        var bits = (transformed & TOP_BIT) != 0u ? (transformed ^ TOP_BIT) : ~transformed;
        return BitConverter.UInt32BitsToSingle(bits);
    }
    // Transforms single values into a byte representation that preserves their natural sort order when compared lexicographically
    public static void Write(float num, Span<byte> buffer, ref int offset)
    {
        const uint TOP_BIT = 0x8000_0000u;
        var bits = BitConverter.SingleToUInt32Bits(num);
        var transformed = (bits & TOP_BIT) != 0u ? ~bits : bits ^ TOP_BIT;
        Write(transformed, buffer, ref offset);
    }
    public static int BytesCount(float _) => 4;



    public static double ReadDouble(ReadOnlySpan<byte> buffer, ref int offset)
    {
        const ulong TOP_BIT = 0x8000_0000_0000_0000UL;
        var transformed = ReadUInt64(buffer, ref offset);
        var bits = (transformed & TOP_BIT) != 0UL ? transformed ^ TOP_BIT : ~transformed;
        return BitConverter.UInt64BitsToDouble(bits);
    }
    // Transforms double values into a byte representation that preserves their natural sort order when compared lexicographically
    public static void Write(double num, Span<byte> buffer, ref int offset)
    {
        const ulong TOP_BIT = 0x8000_0000_0000_0000UL;
        var bits = BitConverter.DoubleToUInt64Bits(num);
        var transformed = (bits & TOP_BIT) != 0UL ? ~bits : bits ^ TOP_BIT;
        Write(transformed, buffer, ref offset);
    }
    public static int BytesCount(double _) => 8;



    public static VarInt ReadVarInt(ReadOnlySpan<byte> buffer, ref int offset)
    {
        ulong accumulated = 0;
        int bytesRead = 0;

        while (true)
        {
            var b = buffer[offset++];
            bytesRead++;

            accumulated = (accumulated << 7) | ((ulong)b & 0x7F);

            if ((b & 0x80) == 0)
                break;
        }

        return (long)(accumulated >> 1) ^ -(long)(accumulated & 1UL);
    }
    public static void Write(VarInt num, Span<byte> buffer, ref int offset)
    {
        ulong z = unchecked(((ulong)(num << 1)) ^ (ulong)(num >> 63));
        int count = BytesCount(num);

        for (int group = count - 1; group >= 0; group--)
        {
            byte b = (byte)((z >> (7 * group)) & 0x7F);
            if (group != 0) b |= 0x80;
            buffer[offset++] = b;
        }
    }
    public static int BytesCount(VarInt num)
    {
        var a = num + num;

        ulong z = unchecked(((ulong)(num << 1)) ^ (ulong)(num >> 63));
        int count = 1;
        ulong tmp = z >> 7;
        while (tmp != 0)
        {
            count++;
            tmp >>= 7;
        }
        return count;
    }



    public static Guid ReadGuid(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var guid = new Guid(buffer.Slice(offset, 16), true);
        offset += 16;
        return guid;
    }
    public static void Write(Guid guid, Span<byte> buffer, ref int offset)
    {
        guid.TryWriteBytes(buffer.Slice(offset, 16), true, out _);
        offset += 16;
    }
    public static int BytesCount(Guid _) => 16;



    public static IPAddress ReadIPAddress(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var len = buffer[offset++];
        if (len != 4 && len != 16)
            throw new InvalidOperationException("Invalid IP address length");
        var ip = new IPAddress(buffer.Slice(offset, len));
        offset += len;
        return ip;
    }
    public static void Write(IPAddress ipAddress, Span<byte> buffer, ref int offset)
    {
        var len = ipAddress.AddressFamily switch
        {
            AddressFamily.InterNetwork => 4,
            AddressFamily.InterNetworkV6 => 16,
            _ => throw new InvalidOperationException("Unsupported address family")
        };
        buffer[offset++] = (byte)len;
        ipAddress.TryWriteBytes(buffer.Slice(offset, len), out _);
        offset += len;
    }
    public static int BytesCount(IPAddress ipAddress)
        => 1 + ipAddress.AddressFamily switch
        {
            AddressFamily.InterNetwork => 4,
            AddressFamily.InterNetworkV6 => 16,
            _ => throw new InvalidOperationException("Unsupported address family")
        };



    public static byte[]? ReadByteArray(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var len = ReadVarInt(buffer, ref offset);
        if (len == -1)
            return null;

        var byteArray = new byte[len];
        buffer.Slice(offset, (int)len).CopyTo(byteArray);
        offset += (int)len;
        return byteArray;
    }
    public static void Write(byte[]? byteArray, Span<byte> buffer, ref int offset)
    {
        if (byteArray is null)
        {
            Write((VarInt)(-1), buffer, ref offset);
        }
        else
        {
            Write((VarInt)byteArray.Length, buffer, ref offset);
            byteArray.CopyTo(buffer.Slice(offset, byteArray.Length));
            offset += byteArray.Length;
        }
    }
    public static int BytesCount(byte[]? byteArray)
    {
        if (byteArray is null)
            return BytesCount((VarInt)(-1));
        else
            return BytesCount((VarInt)byteArray.Length) + byteArray.Length;
    }



    public static string? ReadString(ReadOnlySpan<byte> buffer, ref int offset)
    {
        var len = ReadVarInt(buffer, ref offset);
        if (len == -1)
            return null;

        var str = Encoding.UTF8.GetString(buffer.Slice(offset, (int)len));
        offset += (int)len;
        return str;
    }
    public static void Write(string? str, Span<byte> buffer, ref int offset)
    {
        if (str is null)
        {
            Write((VarInt)(-1), buffer, ref offset);
        }
        else
        {
            var len = Encoding.UTF8.GetByteCount(str);
            Write((VarInt)len, buffer, ref offset);
            Encoding.UTF8.GetBytes(str, buffer.Slice(offset, len));
            offset += len;
        }
    }
    public static int BytesCount(string? str)
    {
        if (str is null)
        {
            return BytesCount((VarInt)(-1));
        }
        else
        {
            var len = Encoding.UTF8.GetByteCount(str);
            return BytesCount((VarInt)len) + len;
        }
    }
}
