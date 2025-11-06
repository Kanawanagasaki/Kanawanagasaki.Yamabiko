namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

internal class EncryptThenMacExtension : IExtension
{
    internal const EExtensionType TYPE = EExtensionType.ENCRYPT_THEN_MAC;
    public EExtensionType Type => TYPE;

    public int Length(bool isRequest)
        => 0;

    public void Write(Span<byte> buffer, bool isRequest) { }

    internal static EncryptThenMacExtension Parse(Span<byte> buffer, bool isRequest)
        => new EncryptThenMacExtension();
}
