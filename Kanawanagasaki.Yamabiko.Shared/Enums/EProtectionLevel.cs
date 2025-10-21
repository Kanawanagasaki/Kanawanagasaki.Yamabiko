namespace Kanawanagasaki.Yamabiko.Shared.Enums;

[Flags]
public enum EProtectionLevel : byte
{
    ANY = 0b0000_0000,

    PASSWORD_PROTECTED = 0b0000_0001,
    PUBLIC = 0b0000_0010
}
