namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public class ServerCertVerifyHandshake : IHandshake
{
    public const EHandshakeType TYPE = EHandshakeType.CERTIFICATE_VERIFY;
    public EHandshakeType Type => TYPE;

    public ESignatureAlgorithm Algorithm { get; }
    public byte[] Signature { get; }

    public ServerCertVerifyHandshake(ESignatureAlgorithm algorithm, byte[] signature)
    {
        Algorithm = algorithm;
        Signature = signature;
    }

    public int Length()
        => 4 + Signature.Length;

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        buffer[0] = (byte)(((ushort)Algorithm >> 8) & 0xFF);
        buffer[1] = (byte)((ushort)Algorithm & 0xFF);

        buffer[2] = (byte)((Signature.Length >> 8) & 0xFF);
        buffer[3] = (byte)(Signature.Length & 0xFF);

        Signature.CopyTo(buffer.Slice(4, Signature.Length));
    }

    public static ServerCertVerifyHandshake Parse(Span<byte> buffer)
    {
        if (buffer.Length < 4)
            throw new FormatException("Buffer too small: cannot read signature algorithm and signature length");

        var algorithm = (ESignatureAlgorithm)((buffer[0] << 8) | buffer[1]);

        if(!Enum.IsDefined(algorithm))
            throw new FormatException("Unsupported signature algorithm");

        var length = (buffer[2] << 8) | buffer[3];

        if(buffer.Length < 4 + length)
            throw new FormatException("Buffer too small: cannot read signature");

        var signature = buffer.Slice(4, length).ToArray();

        return new ServerCertVerifyHandshake(algorithm, signature);
    }
}
