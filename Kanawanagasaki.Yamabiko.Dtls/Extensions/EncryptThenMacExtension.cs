namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public class EncryptThenMacExtension : IExtension
{
    public const EExtensionType TYPE = EExtensionType.ENCRYPT_THEN_MAC;
    public EExtensionType Type => TYPE;

    public int Length(bool isRequest)
        => 0;

    public void Write(Span<byte> buffer, bool isRequest) { }

    public static EncryptThenMacExtension Parse(Span<byte> buffer, bool isRequest)
        => new EncryptThenMacExtension();
}
