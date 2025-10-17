namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public class FinishedHandshake : IHandshake
{
    public const EHandshakeType TYPE = EHandshakeType.FINISHED;
    public EHandshakeType Type => TYPE;

    public byte[] VerifyData { get; }

    public FinishedHandshake(byte[] verifyData)
    {
        VerifyData = verifyData;
    }

    public int Length()
        => VerifyData.Length;

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));
        VerifyData.CopyTo(buffer);
    }

    public static FinishedHandshake Parse(Span<byte> buffer)
        => new FinishedHandshake(buffer.ToArray());
}
