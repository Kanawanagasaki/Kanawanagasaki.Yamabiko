namespace Kanawanagasaki.Yamabiko.Dtls.Enums;

public enum ERecordType : byte
{
    ALERT = 0x15,
    HANDSHAKE = 0x16,
    APPLICATION_DATA = 0x17,
    ACK = 0x1A,
}
