namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class ClientHelloHandshake : IHandshake
{
    public const EHandshakeType TYPE = EHandshakeType.CLIENT_HELLO;
    public EHandshakeType Type => TYPE;

    public EVersions LegacyVersion { get; init; } = EVersions.DTLS1_2;
    public byte[] Random { get; }
    public byte[] LegacySessionId { get; init; } = [];
    public byte[] LegacyCookie { get; init; } = [];
    public ECipherSuite[] CipherSuites { get; }
    public byte[] LegacyCompressionMethods { get; init; } = [0];
    public IExtension[] Extensions { get; }

    public ClientHelloHandshake(byte[] random, ECipherSuite[] cipherSuites, IExtension[] extensions)
    {
        if (random.Length != 32)
            throw new ArgumentException("Random must be 32 bytes long", nameof(random));

        Random = random;
        CipherSuites = cipherSuites;
        Extensions = extensions;
    }

    public int Length()
    {
        int len = 0;

        len += 2; // legacy version

        len += Random.Length;

        len += 1 + LegacySessionId.Length; // session length + session bytes

        len += 1 + LegacyCookie.Length; // cookie length + cookie bytes

        len += 2 + 2 * CipherSuites.Length; // 2 bytes length + 2 bytes per suite

        len += 1 + LegacyCompressionMethods.Length; // methods length + methods bytes

        len += 2 + Extensions.Sum(x => 4 + x.Length(true)); // 2 bytes total length + (2 bytes type + 2 bytes extension length + extension bytes) * for each extension

        return len;
    }

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        int offset = 0;

        buffer[offset++] = (byte)((ushort)LegacyVersion >> 8);
        buffer[offset++] = (byte)((ushort)LegacyVersion & 0xFF);

        Random.CopyTo(buffer[offset..]);
        offset += Random.Length;

        buffer[offset++] = (byte)LegacySessionId.Length;
        if (0 < LegacySessionId.Length)
            LegacySessionId.CopyTo(buffer[offset..]);
        offset += LegacySessionId.Length;

        buffer[offset++] = (byte)LegacyCookie.Length;
        if (0 < LegacyCookie.Length)
            LegacyCookie.CopyTo(buffer[offset..]);
        offset += LegacyCookie.Length;

        var cipherSuitesLen = CipherSuites.Length * 2;
        buffer[offset++] = (byte)((cipherSuitesLen >> 8) & 0xFF);
        buffer[offset++] = (byte)(cipherSuitesLen & 0xFF);
        foreach (var suite in CipherSuites)
        {
            var suiteNum = (ushort)suite;
            buffer[offset++] = (byte)(suiteNum >> 8);
            buffer[offset++] = (byte)(suiteNum & 0xFF);
        }

        buffer[offset++] = (byte)LegacyCompressionMethods.Length;
        LegacyCompressionMethods.CopyTo(buffer[offset..]);
        offset += LegacyCompressionMethods.Length;

        var extensionsLen = Extensions.Sum(x => 4 + x.Length(true));
        buffer[offset++] = (byte)((extensionsLen >> 8) & 0xFF);
        buffer[offset++] = (byte)(extensionsLen & 0xFF);
        foreach (var extension in Extensions)
        {
            buffer[offset++] = (byte)((ushort)extension.Type >> 8);
            buffer[offset++] = (byte)((ushort)extension.Type & 0xFF);

            var extensionLen = extension.Length(true);
            buffer[offset++] = (byte)(extensionLen >> 8);
            buffer[offset++] = (byte)(extensionLen & 0xFF);

            extension.Write(buffer[offset..(offset + extensionLen)], true);
            offset += extensionLen;
        }
    }

    public static ClientHelloHandshake Parse(Span<byte> buffer)
    {
        int offset = 0;


        // legacy version
        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too short: cannot read legacy version");
        var legacyVersion = (EVersions)((buffer[offset++] << 8) | buffer[offset++]);
        if (legacyVersion is not EVersions.DTLS1_2)
            throw new FormatException("Unsupported legacy version");


        // random
        if (buffer.Length < offset + 32)
            throw new FormatException("Buffer too short: cannot read random");
        var random = buffer[offset..(offset + 32)].ToArray();
        offset += 32;


        // legacy session id
        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too short: cannot read legacy session id length");
        var legacySessionIdLen = buffer[offset++];
        if (32 < legacySessionIdLen)
            throw new FormatException("Session ID exceeds 32 bytes");
        if (buffer.Length < offset + legacySessionIdLen)
            throw new FormatException("Buffer too short: cannot read legacy session id");
        var legacySessionId = buffer[offset..(offset + legacySessionIdLen)].ToArray();
        offset += legacySessionIdLen;


        // legacy cookie
        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too short: cannot read legacy cookie length");
        var legacyCookieLen = buffer[offset++];
        if (buffer.Length < offset + legacyCookieLen)
            throw new FormatException("Buffer too short: cannot read legacy cookie");
        var legacyCookie = buffer[offset..(offset + legacyCookieLen)].ToArray();
        offset += legacyCookieLen;


        // cipher suites
        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too short: cannot read cipher suites length");
        var cipherSuitesLen = (buffer[offset++] << 8) | buffer[offset++];
        if (cipherSuitesLen % 2 != 0)
            throw new FormatException("Cipher suites length must be even");
        if (cipherSuitesLen == 0)
            throw new FormatException("At least one cipher suite must be present");
        var cipherSuites = new ECipherSuite[cipherSuitesLen / 2];
        if (buffer.Length < offset + cipherSuitesLen)
            throw new FormatException("Buffer too short: cannot read cipher suites");
        for (int i = 0; i < cipherSuites.Length; i++)
            cipherSuites[i] = (ECipherSuite)((buffer[offset++] << 8) | buffer[offset++]);


        // legacy compression methods
        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too short: cannot read legacy compression methods length");
        var legacyCompressionMethodsLen = buffer[offset++];
        if (buffer.Length < offset + legacyCompressionMethodsLen)
            throw new FormatException("Buffer too short: cannot read legacy compression methods");
        var legacyCompressionMethods = buffer[offset..(offset + legacyCompressionMethodsLen)].ToArray();
        offset += legacyCompressionMethodsLen;


        // extensions
        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too short: cannot read extensions length");
        var extensionsLen = (buffer[offset++] << 8) | buffer[offset++];
        if (buffer.Length < offset + extensionsLen)
            throw new FormatException("Buffer too short: cannot read extensions");

        var extensions = new List<IExtension>();
        var extensionsEnd = offset + extensionsLen;
        while (offset < extensionsEnd)
        {
            if (extensionsEnd < offset + 4)
                throw new FormatException("Extension data length exceeds available buffer size: cannot read extension type and length");
            var extensionTypeNum = (buffer[offset++] << 8) | buffer[offset++];
            var extensionLen = (buffer[offset++] << 8) | buffer[offset++];

            if (extensionsEnd < offset + extensionLen)
                throw new FormatException($"Extension data length exceeds available buffer size: cannot read extension of type 0x{extensionTypeNum:X4}");

            var extension = IExtension.Parse((EExtensionType)extensionTypeNum, buffer.Slice(offset, extensionLen), true);
            if (extension is not null)
                extensions.Add(extension);

            offset += extensionLen;
        }


        return new ClientHelloHandshake(random, cipherSuites, extensions.ToArray())
        {
            LegacyVersion = legacyVersion,
            LegacySessionId = legacySessionId,
            LegacyCookie = legacyCookie,
            LegacyCompressionMethods = legacyCompressionMethods
        };
    }
}
