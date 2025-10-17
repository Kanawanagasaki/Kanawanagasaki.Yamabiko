namespace Kanawanagasaki.Yamabiko.Dtls;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public class PlainTextRecord
{
    public required ERecordType Type { get; init; }
    public EVersions LegacyVersion { get; } = EVersions.DTLS1_2;
    public required ushort KeyEpoch { get; init; }
    public required long RecordNumber { get; init; }

    public byte[] Buffer { get; }

    public PlainTextRecord(byte[] buffer)
    {
        Buffer = buffer;
    }

    public int Length()
    {
        int len = 0;

        len += 1; // tls record type

        len += 2; // protocol version

        len += 2; // key epoch

        len += 6; // sequence number

        len += 2; // data length

        len += Buffer.Length;

        return len;
    }

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        buffer[0] = (byte)Type;

        buffer[1] = (byte)((ushort)LegacyVersion >> 8);
        buffer[2] = (byte)((ushort)LegacyVersion & 0xFF);

        buffer[3] = (byte)(KeyEpoch >> 8);
        buffer[4] = (byte)(KeyEpoch & 0xFF);

        buffer[5] = (byte)((RecordNumber >> 40) & 0xFF);
        buffer[6] = (byte)((RecordNumber >> 32) & 0xFF);
        buffer[7] = (byte)((RecordNumber >> 24) & 0xFF);
        buffer[8] = (byte)((RecordNumber >> 16) & 0xFF);
        buffer[9] = (byte)((RecordNumber >> 8) & 0xFF);
        buffer[10] = (byte)(RecordNumber & 0xFF);

        buffer[11] = (byte)(Buffer.Length >> 8);
        buffer[12] = (byte)(Buffer.Length & 0xFF);

        Buffer.CopyTo(buffer.Slice(13, Buffer.Length));
    }

    public static PlainTextRecord Parse(ReadOnlySpan<byte> buffer, ref int offset)
    {
        if (buffer.Length < offset + 13)
            throw new FormatException("Buffer too small");

        var type = (ERecordType)buffer[offset++];
        if (!Enum.IsDefined(type))
            throw new FormatException("Unknown record type");

        var legacyVersionNum = (buffer[offset++] << 8) | buffer[offset++];
        var legacyVersion = (EVersions)legacyVersionNum;
        if (legacyVersion is not EVersions.DTLS1_2)
            throw new FormatException("Incorrect legacy version");

        var keyEpoch = (ushort)((buffer[offset++] << 8) | buffer[offset++]);

        var sequenceNumber = ((long)buffer[offset++] << 40)
                           | ((long)buffer[offset++] << 32)
                           | ((long)buffer[offset++] << 24)
                           | ((long)buffer[offset++] << 16)
                           | ((long)buffer[offset++] << 8)
                           | buffer[offset++];

        var len = (ushort)((buffer[offset++] << 8) | buffer[offset++]);

        if (buffer.Length < offset + len)
            throw new FormatException("Data length exceeds available buffer size");

        var data = buffer.Slice(offset, len).ToArray();
        offset += len;

        return new PlainTextRecord(data)
        {
            Type = type,
            KeyEpoch = keyEpoch,
            RecordNumber = sequenceNumber
        };
    }
}
