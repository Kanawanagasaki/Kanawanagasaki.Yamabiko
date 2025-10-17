namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public interface IHandshake
{
    public EHandshakeType Type { get; }

    int Length();
    void Write(Span<byte> buffer);

    public static IHandshake? Parse(EHandshakeType type, Span<byte> buffer)
        => type switch
        {
            EHandshakeType.CLIENT_HELLO => ClientHelloHandshake.Parse(buffer),
            EHandshakeType.SERVER_HELLO => ServerHelloHandshake.Parse(buffer),
            EHandshakeType.ENCRYPTED_EXTENSIONS => EncryptedExtensionsHandshake.Parse(buffer),
            EHandshakeType.CERTIFICATE => ServerCertificateHandshake.Parse(buffer),
            EHandshakeType.CERTIFICATE_VERIFY => ServerCertVerifyHandshake.Parse(buffer),
            EHandshakeType.FINISHED => FinishedHandshake.Parse(buffer),
            _ => null
        };
}
