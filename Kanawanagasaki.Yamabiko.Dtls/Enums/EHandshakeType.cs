namespace Kanawanagasaki.Yamabiko.Dtls.Enums;

public enum EHandshakeType : byte
{
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    ENCRYPTED_EXTENSIONS = 0x08,
    CERTIFICATE = 0x0B,
    CERTIFICATE_VERIFY = 0x0F,
    FINISHED = 0x14
}
