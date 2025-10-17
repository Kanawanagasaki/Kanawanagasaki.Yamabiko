namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public sealed class HandshakeFragment
{
    public required EHandshakeType Type { get; init; }
    public required int TotalLength { get; init; }
    public required ushort SequenceNumber { get; init; }
    public required int FragmentOffset { get; init; }

    public int FragmentLength => Fragment.Length;

    public byte[] Fragment { get; }

    public HandshakeFragment(byte[] fragment)
    {
        Fragment = fragment;
    }

    public int Length()
    {
        int len = 0;

        len += 1; // 1 byte type

        len += 3; // 3 bytes total length

        len += 2; // 2 bytes message seq

        len += 3; // 3 bytes fragment offset

        len += 3; // 3 bytes fragment length

        len += Fragment.Length;

        return len;
    }

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new FormatException("Buffer too small");

        buffer[0] = (byte)Type;

        buffer[1] = (byte)((TotalLength >> 16) & 0xFF);
        buffer[2] = (byte)((TotalLength >> 8) & 0xFF);
        buffer[3] = (byte)(TotalLength & 0xFF);

        buffer[4] = (byte)((SequenceNumber >> 8) & 0xFF);
        buffer[5] = (byte)(SequenceNumber & 0xFF);

        buffer[6] = (byte)((FragmentOffset >> 16) & 0xFF);
        buffer[7] = (byte)((FragmentOffset >> 8) & 0xFF);
        buffer[8] = (byte)(FragmentOffset & 0xFF);

        buffer[9] = (byte)((FragmentLength >> 16) & 0xFF);
        buffer[10] = (byte)((FragmentLength >> 8) & 0xFF);
        buffer[11] = (byte)(FragmentLength & 0xFF);

        Fragment.CopyTo(buffer[12..]);
    }

    public static HandshakeFragment Parse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 12)
            throw new ArgumentException("Buffer too small", nameof(buffer));

        var type = (EHandshakeType)buffer[0];
        var totalLength = (buffer[1] << 16) | (buffer[2] << 8) | buffer[3];
        var sequenceNum = (ushort)((buffer[4] << 8) | buffer[5]);
        var fragmentOffset = (buffer[6] << 16) | (buffer[7] << 8) | buffer[8];
        var fragmentLength = (buffer[9] << 16) | (buffer[10] << 8) | buffer[11];

        if (0xFFFFFF < totalLength)
            throw new FormatException("Total length out of range");
        if (0xFFFFFF < fragmentOffset)
            throw new FormatException("Fragment offset out of range");
        if (0xFFFFFF < fragmentLength)
            throw new FormatException("Fragment length out of range");

        if (totalLength < fragmentOffset + fragmentLength)
            throw new FormatException("Mismatch between total length and fragment offset + length");

        if (buffer.Length - 12 < fragmentLength)
            throw new FormatException("Buffer too small: cannot read fragment");

        return new HandshakeFragment(buffer.Slice(12, fragmentLength).ToArray())
        {
            Type = type,
            TotalLength = totalLength,
            SequenceNumber = sequenceNum,
            FragmentOffset = fragmentOffset
        };
    }
}
