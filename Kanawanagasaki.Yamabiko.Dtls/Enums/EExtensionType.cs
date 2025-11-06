namespace Kanawanagasaki.Yamabiko.Dtls.Enums;

internal enum EExtensionType : ushort
{
    UNKNOWN = 0x0000,
    SUPPORTED_GROUPS = 0x000A,
    SIGNATURE_ALGORITHMS = 0x000D,
    ENCRYPT_THEN_MAC = 0x0016,
    SUPPORTED_VERSIONS = 0x002B,
    KEY_SHARE = 0x0033,
    CONNECTION_ID = 0x0036
}
