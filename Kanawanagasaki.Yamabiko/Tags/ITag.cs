namespace Kanawanagasaki.Yamabiko.Tags;

public interface ITag
{
    byte TagId { get; }
    byte[] ToByteArray();

    public static T? Parse<T>(byte tagId, ReadOnlySpan<byte> buffer) where T : class, ITag
    {
        if (typeof(T) == typeof(ByteArrayTag))
            return (T)(object)ByteArrayTag.Parse(tagId, buffer);
        if (typeof(T) == typeof(ByteTag))
            return (T)(object)ByteTag.Parse(tagId, buffer);
        if (typeof(T) == typeof(DoubleTag))
            return (T)(object)DoubleTag.Parse(tagId, buffer);
        if (typeof(T) == typeof(FloatTag))
            return (T)(object)FloatTag.Parse(tagId, buffer);
        if (typeof(T) == typeof(IntTag))
            return (T)(object)IntTag.Parse(tagId, buffer);
        if (typeof(T) == typeof(LongTag))
            return (T)(object)LongTag.Parse(tagId, buffer);
        if (typeof(T) == typeof(ShortTag))
            return (T)(object)ShortTag.Parse(tagId, buffer);
        if (typeof(T) == typeof(StringTag))
            return (T)(object)StringTag.Parse(tagId, buffer);

        return null;
    }
}
