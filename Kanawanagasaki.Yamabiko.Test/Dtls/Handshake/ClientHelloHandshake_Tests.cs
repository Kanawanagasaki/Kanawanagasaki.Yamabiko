namespace Kanawanagasaki.Yamabiko.Test.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;
using Kanawanagasaki.Yamabiko.Dtls.Handshake;

public class ClientHelloHandshake_Tests
{
    [Fact]
    public void ParseAndWrite()
    {
        var data = new byte[] { 0xfe, 0xfd, 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff, 0x00, 0x00, 0x00, 0x06, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0x01, 0x00, 0x00, 0x61, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54, 0x00, 0x2b, 0x00, 0x03, 0x02, 0xfe, 0xfc, 0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x03, 0x05, 0x03, 0x04, 0x03, 0x02, 0x03, 0x08, 0x06, 0x08, 0x0b, 0x08, 0x05, 0x08, 0x0a, 0x08, 0x04, 0x08, 0x09, 0x06, 0x01, 0x05, 0x01, 0x04, 0x01, 0x03, 0x01, 0x02, 0x01, 0x00, 0x16, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d };
        var clientHello = ClientHelloHandshake.Parse(data);

        Assert.Equal(0xfefd, (ushort)clientHello.LegacyVersion);

        var random = new byte[] { 0xe0, 0xe1, 0xe2, 0xe3, 0xe4, 0xe5, 0xe6, 0xe7, 0xe8, 0xe9, 0xea, 0xeb, 0xec, 0xed, 0xee, 0xef, 0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff };
        Assert.Equal(random, clientHello.Random);

        Assert.Empty(clientHello.LegacySessionId);

        Assert.Empty(clientHello.LegacyCookie);

        Assert.Equal(3, clientHello.CipherSuites.Length);
        Assert.Contains(ECipherSuite.TLS_AES_128_GCM_SHA256, clientHello.CipherSuites);
        Assert.Contains(ECipherSuite.TLS_AES_256_GCM_SHA384, clientHello.CipherSuites);
        Assert.Contains(ECipherSuite.TLS_CHACHA20_POLY1305_SHA256, clientHello.CipherSuites);

        var legacyCompressionMethod = Assert.Single(clientHello.LegacyCompressionMethods);
        Assert.Equal(0, legacyCompressionMethod);

        Assert.Equal(5, clientHello.Extensions.Length);

        var keyShare = Assert.IsType<KeyShareExtension>(clientHello.Extensions[0]);
        var (group, groupKey) = Assert.Single(keyShare.GroupToKey);
        Assert.Equal(ENamedGroup.X25519, group);
        var key = new byte[] { 0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea, 0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0, 0xd2, 0xcd, 0x16, 0x62, 0x54 };
        Assert.Equal(key, groupKey);

        var supportedVersions = Assert.IsType<SupportedVersionsExtension>(clientHello.Extensions[1]);
        var supportedVersion = Assert.Single(supportedVersions.Versions);
        Assert.Equal(EVersions.DTLS1_3, supportedVersion);

        var signatureAlgorithms = Assert.IsType<SignatureAlgorithmsExtension>(clientHello.Extensions[2]);
        Assert.Equal(15, signatureAlgorithms.Algorithms.Length);
        Assert.Contains(ESignatureAlgorithm.ECDSA_SECP512R1_SHA512, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.ECDSA_SECP384R1_SHA384, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.ECDSA_SECP256R1_SHA256, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.ECDSA_SHA1, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PSS_RSAE_SHA512, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PSS_PSS_SHA512, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PSS_RSAE_SHA384, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PSS_PSS_SHA384, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PSS_RSAE_SHA256, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PSS_PSS_SHA256, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PKCS1_SHA512, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PKCS1_SHA384, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PKCS1_SHA256, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.RSA_PKCS1_SHA1, signatureAlgorithms.Algorithms);
        Assert.Contains(ESignatureAlgorithm.SHA224_RSA, signatureAlgorithms.Algorithms);

        Assert.IsType<EncryptThenMacExtension>(clientHello.Extensions[3]);

        var supportedGroups = Assert.IsType<SupportedGroupsExtension>(clientHello.Extensions[4]);
        var group2 = Assert.Single(supportedGroups.Groups);
        Assert.Equal(ENamedGroup.X25519, group2);

        var length = clientHello.Length();
        Assert.Equal(data.Length, length);

        var buffer = new byte[length];
        clientHello.Write(buffer);
        Assert.Equal(data, buffer);
    }
}
