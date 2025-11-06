namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

internal class SupportedVersionsExtension : IExtension
{
    internal const EExtensionType TYPE = EExtensionType.SUPPORTED_VERSIONS;
    public EExtensionType Type => TYPE;

    internal EVersions[] Versions { get; }

    internal SupportedVersionsExtension(EVersions[] versions)
    {
        Versions = versions;
    }

    public int Length(bool isRequest)
    {
        if (isRequest)
            return 1 + Versions.Length * 2;
        else
            return 2;
    }

    public void Write(Span<byte> buffer, bool isRequest)
    {
        if (buffer.Length < Length(isRequest))
            throw new ArgumentException("Buffer too small", nameof(buffer));

        if (isRequest)
        {
            int offset = 0;

            var len = Versions.Length * 2;
            if (byte.MaxValue < len)
                throw new FormatException($"Extension data length exceeds {byte.MaxValue} bytes");

            buffer[offset++] = (byte)len;

            for (int i = 0; i < Versions.Length; i++)
            {
                var versionNum = (ushort)Versions[i];
                buffer[offset++] = (byte)(versionNum >> 8);
                buffer[offset++] = (byte)(versionNum & 0xFF);
            }
        }
        else
        {
            if (Versions.Length != 1)
                throw new FormatException("There should be only one version in response");

            var versionNum = (ushort)Versions[0];
            buffer[0] = (byte)(versionNum >> 8);
            buffer[1] = (byte)(versionNum & 0xFF);
        }
    }

    internal static SupportedVersionsExtension Parse(Span<byte> buffer, bool isRequest)
    {
        if (isRequest)
        {
            int offset = 0;

            var len = buffer[offset++];
            var dataEnd = offset + len;

            if (buffer.Length < dataEnd)
                throw new FormatException("Extension data length exceeds available buffer size");

            if (len % 2 != 0)
                throw new FormatException("Extension data length must be even");

            var versions = new EVersions[len / 2];

            if (versions.Length == 0)
                throw new FormatException("At least version must be specified");

            for (int i = 0; i < versions.Length; i++)
            {
                var versionNum = (buffer[offset++] << 8) | buffer[offset++];
                var version = (EVersions)versionNum;

                if (!Enum.IsDefined(version))
                    throw new FormatException($"Unsupported or invalid version: 0x{versionNum:X4}");

                versions[i] = version;
            }

            return new SupportedVersionsExtension(versions);
        }
        else
        {
            if (buffer.Length < 2)
                throw new FormatException("Extension data length exceeds available buffer size");

            var versionNum = (buffer[0] << 8) | buffer[1];
            var versions = new EVersions[] { (EVersions)versionNum };
            return new SupportedVersionsExtension(versions);
        }
    }
}
