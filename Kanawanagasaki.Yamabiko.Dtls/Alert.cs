namespace Kanawanagasaki.Yamabiko.Dtls;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public class Alert
{
    public byte Level { get; init; }
    public EAlertType Type { get; }

    public Alert(EAlertType type)
    {
        Level = (byte)(type is EAlertType.CLOSE_NOTIFY or EAlertType.USER_CANCELED ? 1 : 2);
        Type = type;
    }

    public int Length()
        => 2;

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        buffer[0] = Level;
        buffer[1] = (byte)Type;
    }

    public static Alert Parse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 2)
            throw new FormatException("Buffer too small");

        return new Alert((EAlertType)buffer[1])
        {
            Level = buffer[0]
        };
    }
}
