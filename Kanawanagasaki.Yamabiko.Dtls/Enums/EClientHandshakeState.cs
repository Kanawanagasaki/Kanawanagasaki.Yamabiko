namespace Kanawanagasaki.Yamabiko.Dtls.Enums;

public enum EClientHandshakeState
{
    NONE = 0x0,
    STARTED = 0x1,
    WAITING_SERVER_HELLO = 0x2,
    WAITING_ENCRYPTED_EXTENSIONS = 0x3,
    WAITING_CERTIFICATE = 0x4,
    WAITING_CERTIFICATE_VERIFY = 0x5,
    WAITING_HANDSHAKE_FINISHED = 0x6,
    WAITING_ACK = 0x7,
    FAILED = 0xFE,
    DONE = 0xFF
}
