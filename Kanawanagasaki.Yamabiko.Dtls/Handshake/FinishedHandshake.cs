namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

internal class FinishedHandshake : IHandshake
{
    internal const EHandshakeType TYPE = EHandshakeType.FINISHED;
    public EHandshakeType Type => TYPE;

    internal byte[] VerifyData { get; }

    internal FinishedHandshake(byte[] verifyData)
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

    internal static FinishedHandshake Parse(Span<byte> buffer)
        => new FinishedHandshake(buffer.ToArray());
}
