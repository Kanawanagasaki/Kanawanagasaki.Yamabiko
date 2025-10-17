namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public interface IExtension
{
    EExtensionType Type { get; }
    int Length(bool isRequest);
    void Write(Span<byte> buffer, bool isRequest);

    public static IExtension? Parse(EExtensionType type, Span<byte> buffer, bool isRequest)
        => type switch
        {
            SupportedGroupsExtension.TYPE => SupportedGroupsExtension.Parse(buffer, isRequest),
            SignatureAlgorithmsExtension.TYPE => SignatureAlgorithmsExtension.Parse(buffer, isRequest),
            EncryptThenMacExtension.TYPE => EncryptThenMacExtension.Parse(buffer, isRequest),
            SupportedVersionsExtension.TYPE => SupportedVersionsExtension.Parse(buffer, isRequest),
            KeyShareExtension.TYPE => KeyShareExtension.Parse(buffer, isRequest),
            ConnectionIdExtension.TYPE => ConnectionIdExtension.Parse(buffer, isRequest),
            _ => null
        };
}
