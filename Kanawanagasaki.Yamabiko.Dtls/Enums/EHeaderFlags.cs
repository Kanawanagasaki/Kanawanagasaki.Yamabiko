namespace Kanawanagasaki.Yamabiko.Dtls.Enums;

[Flags]
public enum EHeaderFlags : byte
{
    NONE = 0b0000_0000,
    FIXED_BITS = 0b1110_0000,
    HAS_CONNECTION_ID = 0b0001_0000,
    IS_RECORD_NUMBER_2_BYTES = 0b0000_1000,
    HAS_LENGTH_FIELD = 0b0000_0100,
    ENCRYPTION_EPOCH = 0b0000_0011
}
