namespace Kanawanagasaki.Yamabiko.Sample;

using Kanawanagasaki.Yamabiko;
using Kanawanagasaki.Yamabiko.Tags;

public static class KcpTagCodec
{
    public const byte TagReliableNoDelay = 1;
    public const byte TagReliableIntervalMs = 2;
    public const byte TagReliableFastResend = 3;
    public const byte TagReliableNoCongestionControl = 4;
    public const byte TagReliableSendWindowSize = 5;
    public const byte TagReliableRecvWindowSize = 6;
    public const byte TagReliableMtu = 7;
    public const byte TagStreamNoDelay = 8;
    public const byte TagStreamIntervalMs = 9;
    public const byte TagStreamFastResend = 10;
    public const byte TagStreamNoCongestionControl = 11;
    public const byte TagStreamSendWindowSize = 12;
    public const byte TagStreamRecvWindowSize = 13;
    public const byte TagStreamMtu = 14;

    public static IEnumerable<ITag> ToTags(YamabikoKcpOptions options)
    {
        yield return new ByteTag(TagReliableNoDelay, (byte)(options.ReliableNoDelay ? 1 : 0));
        yield return new IntTag(TagReliableIntervalMs, options.ReliableIntervalMs);
        yield return new IntTag(TagReliableFastResend, options.ReliableFastResend);
        yield return new ByteTag(TagReliableNoCongestionControl, (byte)(options.ReliableNoCongestionControl ? 1 : 0));
        yield return new IntTag(TagReliableSendWindowSize, options.ReliableSendWindowSize);
        yield return new IntTag(TagReliableRecvWindowSize, options.ReliableRecvWindowSize);
        yield return new IntTag(TagReliableMtu, options.ReliableMtu);

        yield return new ByteTag(TagStreamNoDelay, (byte)(options.StreamNoDelay ? 1 : 0));
        yield return new IntTag(TagStreamIntervalMs, options.StreamIntervalMs);
        yield return new IntTag(TagStreamFastResend, options.StreamFastResend);
        yield return new ByteTag(TagStreamNoCongestionControl, (byte)(options.StreamNoCongestionControl ? 1 : 0));
        yield return new IntTag(TagStreamSendWindowSize, options.StreamSendWindowSize);
        yield return new IntTag(TagStreamRecvWindowSize, options.StreamRecvWindowSize);
        yield return new IntTag(TagStreamMtu, options.StreamMtu);
    }

    public static YamabikoKcpOptions FromTags(IReadOnlyDictionary<byte, byte[]> tags)
        => new YamabikoKcpOptions
        {
            ReliableNoDelay = TryGetByte(tags, TagReliableNoDelay, 1) == 1,
            ReliableIntervalMs = TryGetInt(tags, TagReliableIntervalMs, 10),
            ReliableFastResend = TryGetInt(tags, TagReliableFastResend, 2),
            ReliableNoCongestionControl = TryGetByte(tags, TagReliableNoCongestionControl, 0) == 1,
            ReliableSendWindowSize = TryGetInt(tags, TagReliableSendWindowSize, 128),
            ReliableRecvWindowSize = TryGetInt(tags, TagReliableRecvWindowSize, 256),
            ReliableMtu = TryGetInt(tags, TagReliableMtu, 1300),

            StreamNoDelay = TryGetByte(tags, TagStreamNoDelay, 0) == 1,
            StreamIntervalMs = TryGetInt(tags, TagStreamIntervalMs, 40),
            StreamFastResend = TryGetInt(tags, TagStreamFastResend, 0),
            StreamNoCongestionControl = TryGetByte(tags, TagStreamNoCongestionControl, 0) == 1,
            StreamSendWindowSize = TryGetInt(tags, TagStreamSendWindowSize, 256),
            StreamRecvWindowSize = TryGetInt(tags, TagStreamRecvWindowSize, 512),
            StreamMtu = TryGetInt(tags, TagStreamMtu, 1300),
        };

    public static byte TryGetByte(IReadOnlyDictionary<byte, byte[]> tags, byte tagId, byte defaultValue)
    {
        if (!tags.TryGetValue(tagId, out var data) || data.Length == 0)
            return defaultValue;
        return data[0];
    }

    public static int TryGetInt(IReadOnlyDictionary<byte, byte[]> tags, byte tagId, int defaultValue)
    {
        if (!tags.TryGetValue(tagId, out var data) || data.Length < 4)
            return defaultValue;
        var tag = IntTag.Parse(tagId, data);
        return tag.Val;
    }
}
