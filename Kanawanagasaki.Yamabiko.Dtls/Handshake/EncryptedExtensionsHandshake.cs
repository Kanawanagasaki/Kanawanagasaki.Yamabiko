namespace Kanawanagasaki.Yamabiko.Dtls.Handshake;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using Kanawanagasaki.Yamabiko.Dtls.Extensions;
using System;

public class EncryptedExtensionsHandshake : IHandshake
{
    public const EHandshakeType TYPE = EHandshakeType.ENCRYPTED_EXTENSIONS;
    public EHandshakeType Type => TYPE;

    public IExtension[] Extensions { get; }

    public EncryptedExtensionsHandshake(IExtension[] extensions)
    {
        Extensions = extensions;
    }

    public int Length()
        => 2 + Extensions.Sum(x => 4 + x.Length(false));

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        int offset = 0;

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

    public static EncryptedExtensionsHandshake Parse(Span<byte> buffer)
    {
        int offset = 0;

        if (buffer.Length < 2)
            throw new ArgumentException("Buffer too small: cannot read extensions length", nameof(buffer));
        int extensionsLen = (buffer[offset++] << 8) | buffer[offset++];
        if (buffer.Length < extensionsLen)
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

        return new EncryptedExtensionsHandshake(extensions.ToArray());
    }
}
