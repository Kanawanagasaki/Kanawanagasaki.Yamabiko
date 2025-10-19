namespace Kanawanagasaki.Yamabiko.Shared.Enums;

[Flags]
public enum EProtectionLevel : byte
{
    PASSWORD_PROTECTED = 0b0000_0001,
    PUBLIC = 0b0000_0010,

    ALL = 0b1111_1111
}
