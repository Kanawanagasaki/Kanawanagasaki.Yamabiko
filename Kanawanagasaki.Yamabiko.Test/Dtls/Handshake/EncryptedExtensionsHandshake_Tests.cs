namespace Kanawanagasaki.Yamabiko.Test.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;
using Kanawanagasaki.Yamabiko.Dtls.Handshake;

public class EncryptedExtensionsHandshake_Tests
{
    [Fact]
    public void ParseAndWrite()
    {
        var data = new byte[] { 0x00, 0x10, 0x00, 0x0a, 0x00, 0x0c, 0x00, 0x0a, 0x00, 0x17, 0x00, 0x1d, 0x00, 0x18, 0x00, 0x19, 0x01, 0x00 };

        var encryptedExtensions = EncryptedExtensionsHandshake.Parse(data);
        var extension = Assert.Single(encryptedExtensions.Extensions);
        var supportedGroups = Assert.IsType<SupportedGroupsExtension>(extension);
        Assert.Equal(5, supportedGroups.Groups.Length);
        Assert.Contains(ENamedGroup.SECP256R1, supportedGroups.Groups);
        Assert.Contains(ENamedGroup.X25519, supportedGroups.Groups);
        Assert.Contains(ENamedGroup.SECP384R1, supportedGroups.Groups);
        Assert.Contains(ENamedGroup.SECP521R1, supportedGroups.Groups);
        Assert.Contains(ENamedGroup.FFDHE2048, supportedGroups.Groups);

        var length = encryptedExtensions.Length();
        Assert.Equal(data.Length, length);

        var buffer = new byte[length];
        encryptedExtensions.Write(buffer);
        Assert.Equal(data, buffer);
    }
}
