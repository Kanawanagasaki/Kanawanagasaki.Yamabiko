namespace Kanawanagasaki.Yamabiko.Dtls;

public class Ack
{
    public ulong Epoch { get; }
    public ulong RecordNumber { get; }

    public Ack(ulong epoch, ulong sequenceNumber)
    {
        Epoch = epoch;
        RecordNumber = sequenceNumber;
    }

    public int Length()
        => 2 + 8 + 8;

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        buffer[0] = 0;
        buffer[1] = 16;

        buffer[2] = (byte)((Epoch >> 56) & 0xFF);
        buffer[3] = (byte)((Epoch >> 48) & 0xFF);
        buffer[4] = (byte)((Epoch >> 40) & 0xFF);
        buffer[5] = (byte)((Epoch >> 32) & 0xFF);
        buffer[6] = (byte)((Epoch >> 24) & 0xFF);
        buffer[7] = (byte)((Epoch >> 16) & 0xFF);
        buffer[8] = (byte)((Epoch >> 8) & 0xFF);
        buffer[9] = (byte)(Epoch & 0xFF);

        buffer[10] = (byte)((RecordNumber >> 56) & 0xFF);
        buffer[11] = (byte)((RecordNumber >> 48) & 0xFF);
        buffer[12] = (byte)((RecordNumber >> 40) & 0xFF);
        buffer[13] = (byte)((RecordNumber >> 32) & 0xFF);
        buffer[14] = (byte)((RecordNumber >> 24) & 0xFF);
        buffer[15] = (byte)((RecordNumber >> 16) & 0xFF);
        buffer[16] = (byte)((RecordNumber >> 8) & 0xFF);
        buffer[17] = (byte)(RecordNumber & 0xFF);
    }

    public static Ack Parse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 18)
            throw new FormatException("Buffer too small");

        var len = (buffer[0] << 8) | buffer[1];
        if (len != 16)
            throw new FormatException("Incorrect length");

        var epoch = ((ulong)buffer[2] << 56)
                  | ((ulong)buffer[3] << 48)
                  | ((ulong)buffer[4] << 40)
                  | ((ulong)buffer[5] << 32)
                  | ((ulong)buffer[6] << 24)
                  | ((ulong)buffer[7] << 16)
                  | ((ulong)buffer[8] << 8)
                  | (ulong)buffer[9];

        var seqNum = ((ulong)buffer[10] << 56)
                   | ((ulong)buffer[11] << 48)
                   | ((ulong)buffer[12] << 40)
                   | ((ulong)buffer[13] << 32)
                   | ((ulong)buffer[14] << 24)
                   | ((ulong)buffer[15] << 16)
                   | ((ulong)buffer[16] << 8)
                   | (ulong)buffer[17];

        return new Ack(epoch, seqNum);
    }
}
