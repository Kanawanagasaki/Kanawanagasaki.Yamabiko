namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

public class SupportedGroupsExtension : IExtension
{
    public const EExtensionType TYPE = EExtensionType.SUPPORTED_GROUPS;
    public EExtensionType Type => TYPE;

    public ENamedGroup[] Groups { get; }

    public SupportedGroupsExtension(ENamedGroup[] groups)
    {
        Groups = groups;
    }

    public int Length(bool isRequest)
        => 2 + Groups.Length * 2;

    public void Write(Span<byte> buffer, bool isRequest)
    {
        if (buffer.Length < Length(isRequest))
            throw new ArgumentException("Buffer too small", nameof(buffer));

        int offset = 0;

        var len = Groups.Length * 2;
        if (ushort.MaxValue < len)
            throw new FormatException($"Extension data length exceeds {ushort.MaxValue} bytes");

        buffer[offset++] = (byte)((len >> 8) & 0xFF);
        buffer[offset++] = (byte)(len & 0xFF);

        for (int i = 0; i < Groups.Length; i++)
        {
            var groupNum = (ushort)Groups[i];
            buffer[offset++] = (byte)(groupNum >> 8);
            buffer[offset++] = (byte)(groupNum & 0xFF);
        }
    }

    public static SupportedGroupsExtension Parse(Span<byte> buffer, bool isRequest)
    {
        int offset = 0;

        int len = (buffer[offset++] << 8) | buffer[offset++];
        var dataEnd = offset + len;

        if (buffer.Length < dataEnd)
            throw new FormatException("Extension data length exceeds available buffer size");

        if (len % 2 != 0)
            throw new FormatException("Extension data length must be even");

        var groups = new ENamedGroup[len / 2];

        if (groups.Length == 0)
            throw new FormatException("At least one named group must be specified");

        for (int i = 0; i < groups.Length; i++)
        {
            var groupNum = (buffer[offset++] << 8) | buffer[offset++];
            var group = (ENamedGroup)groupNum;

            if (!Enum.IsDefined(group))
                throw new FormatException($"Unsupported or invalid named group: 0x{groupNum:X4}");

            groups[i] = group;
        }

        return new SupportedGroupsExtension(groups);
    }
}
