namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

internal class KeyShareExtension : IExtension
{
    internal const EExtensionType TYPE = EExtensionType.KEY_SHARE;
    public EExtensionType Type => TYPE;

    internal IReadOnlyDictionary<ENamedGroup, byte[]> GroupToKey { get; }

    internal KeyShareExtension(Dictionary<ENamedGroup, byte[]> groupToKey)
    {
        GroupToKey = groupToKey.AsReadOnly();
    }

    public int Length(bool isRequest)
    {
        if (isRequest)
            return 2 + GroupToKey.Values.Sum(x => 4 + x.Length); // 2 bytes length + (2 bytes for group keycode + 2 bytes key length + key bytes) * entries count
        else
            return GroupToKey.Values.Sum(x => 4 + x.Length); // (2 bytes for group keycode + 2 bytes key length + key bytes) * entries count
    }

    public void Write(Span<byte> buffer, bool isRequest)
    {
        if (buffer.Length < Length(isRequest))
            throw new ArgumentException("Buffer too small", nameof(buffer));

        int offset = 0;

        var len = GroupToKey.Values.Sum(x => 4 + x.Length);
        if (ushort.MaxValue < len)
            throw new FormatException($"Extension data length exceeds {ushort.MaxValue} bytes");

        if (isRequest)
        {
            buffer[offset++] = (byte)((len >> 8) & 0xFF);
            buffer[offset++] = (byte)(len & 0xFF);
        }
        else if (GroupToKey.Count != 1)
            throw new FormatException("There should be only one group:key in response");

        foreach (var (group, key) in GroupToKey)
        {
            var groupNum = (ushort)group;
            buffer[offset++] = (byte)(groupNum >> 8);
            buffer[offset++] = (byte)(groupNum & 0xFF);

            if (ushort.MaxValue < key.Length)
                throw new FormatException($"Key length for group {group} exceeds {ushort.MaxValue} bytes");

            buffer[offset++] = (byte)((key.Length >> 8) & 0xFF);
            buffer[offset++] = (byte)(key.Length & 0xFF);

            key.CopyTo(buffer[offset..]);

            offset += key.Length;
        }
    }

    internal static KeyShareExtension Parse(Span<byte> buffer, bool isRequest)
    {
        if (isRequest)
        {
            if (buffer.Length < 2)
                throw new FormatException("Buffer too small to read extension length");

            var groupToKey = new Dictionary<ENamedGroup, byte[]>();

            int offset = 0;

            var len = (buffer[offset++] << 8) | buffer[offset++];
            var dataEnd = offset + len;

            if (buffer.Length < dataEnd)
                throw new FormatException("Extension data length exceeds available buffer size");

            while (offset < dataEnd)
            {
                if (dataEnd < offset + 4)
                    throw new FormatException("Insufficient data to read group and key length");

                var groupNum = (buffer[offset++] << 8) | buffer[offset++];
                var keyLength = (buffer[offset++] << 8) | buffer[offset++];

                if (dataEnd < offset + keyLength)
                    throw new FormatException("Key length exceeds available data");

                if (0 < keyLength)
                    groupToKey[(ENamedGroup)groupNum] = buffer.Slice(offset, keyLength).ToArray();

                offset += keyLength;
            }

            return new KeyShareExtension(groupToKey);
        }
        else
        {
            if (buffer.Length < 4)
                throw new FormatException("Insufficient data to read group and key length");

            var groupToKey = new Dictionary<ENamedGroup, byte[]>();

            var groupNum = (buffer[0] << 8) | buffer[1];
            var keyLength = (buffer[2] << 8) | buffer[3];

            if (buffer.Length < 4 + keyLength)
                throw new FormatException("Key length exceeds available data");

            groupToKey[(ENamedGroup)groupNum] = buffer.Slice(4, keyLength).ToArray();

            return new KeyShareExtension(groupToKey);
        }
    }
}
