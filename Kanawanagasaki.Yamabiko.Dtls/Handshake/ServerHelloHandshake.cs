namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;

public class ServerHelloHandshake : IHandshake
{
    public const EHandshakeType TYPE = EHandshakeType.SERVER_HELLO;
    public EHandshakeType Type => TYPE;

    public EVersions LegacyVersion { get; init; } = EVersions.DTLS1_2;
    public byte[] Random { get; }
    public byte[] LegacySessionId { get; init; } = [];
    public ECipherSuite CipherSuite { get; }
    public byte CompressionMethod { get; init; } = 0x00;
    public IExtension[] Extensions { get; }

    public ServerHelloHandshake(byte[] random, ECipherSuite cipherSuite, IExtension[] extensions)
    {
        if (random.Length != 32)
            throw new ArgumentException("Random must be 32 bytes long", nameof(random));

        Random = random;
        CipherSuite = cipherSuite;
        Extensions = extensions;
    }

    public int Length()
    {
        int len = 0;

        len += 2; // legacy version

        len += Random.Length;

        len += 1 + LegacySessionId.Length;  // session length + session bytes

        len += 2; // cipher suite

        len += 1; // compression method

        len += 2 + Extensions.Sum(x => 4 + x.Length(false)); // 2 bytes total length + (2 bytes type + 2 bytes extension length + extension bytes) * for each extension

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

        var cipherSuiteNum = (ushort)CipherSuite;
        buffer[offset++] = (byte)(cipherSuiteNum >> 8);
        buffer[offset++] = (byte)(cipherSuiteNum & 0xFF);

        buffer[offset++] = CompressionMethod;

        var extensionsLen = Extensions.Sum(x => 4 + x.Length(false));
        buffer[offset++] = (byte)((extensionsLen >> 8) & 0xFF);
        buffer[offset++] = (byte)(extensionsLen & 0xFF);
        foreach (var extension in Extensions)
        {
            buffer[offset++] = (byte)((ushort)extension.Type >> 8);
            buffer[offset++] = (byte)((ushort)extension.Type & 0xFF);

            var extensionLen = extension.Length(false);
            buffer[offset++] = (byte)(extensionLen >> 8);
            buffer[offset++] = (byte)(extensionLen & 0xFF);

            extension.Write(buffer[offset..(offset + extensionLen)], false);
            offset += extensionLen;
        }
    }

    public static ServerHelloHandshake Parse(Span<byte> buffer)
    {
        int offset = 0;


        // legacy version
        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too small: cannot read legacy version");
        var legacyVersion = (EVersions)((buffer[offset++] << 8) | buffer[offset++]);
        if (legacyVersion is not EVersions.DTLS1_2)
            throw new FormatException("Unsupported legacy version");


        // random
        if (buffer.Length < offset + 32)
            throw new FormatException("Buffer too small: cannot read random");
        var random = buffer[offset..(offset + 32)].ToArray();
        offset += 32;


        // legacy session id
        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read legacy session id length");
        var legacySessionIdLen = buffer[offset++];
        if (32 < legacySessionIdLen)
            throw new FormatException("Session ID exceeds 32 bytes");
        if (buffer.Length < offset + legacySessionIdLen)
            throw new FormatException("Buffer too small: cannot read legacy session id");
        var legacySessionId = buffer[offset..(offset + legacySessionIdLen)].ToArray();
        offset += legacySessionIdLen;


        // cipher suite
        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too small: cannot read cipher suite");
        var cipherSuite = (ECipherSuite)((buffer[offset++] << 8) | buffer[offset++]);
        if (!Enum.IsDefined(cipherSuite))
            throw new FormatException("Unsupported cipher suite");


        // legacy compression method
        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read compression method");
        var compressionMethod = buffer[offset++];


        // extensions
        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too small: cannot read extensions length");
        var extensionsLen = (buffer[offset++] << 8) | buffer[offset++];
        if (buffer.Length < offset + extensionsLen)
            throw new FormatException("Buffer too small: cannot read extensions");

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

            var extension = IExtension.Parse((EExtensionType)extensionTypeNum, buffer.Slice(offset, extensionLen), false);
            if (extension is not null)
                extensions.Add(extension);

            offset += extensionLen;
        }


        return new ServerHelloHandshake(random, cipherSuite, extensions.ToArray())
        {
            LegacyVersion = legacyVersion,
            LegacySessionId = legacySessionId,
            CompressionMethod = compressionMethod
        };
    }
}
