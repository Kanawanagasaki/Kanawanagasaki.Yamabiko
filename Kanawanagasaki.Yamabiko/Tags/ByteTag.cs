namespace Kanawanagasaki.Yamabiko.Tags;

public class ByteTag : ITag
{
    public byte TagId { get; }
    public byte Val { get; }

    public ByteTag(byte tagId, byte val)
    {
        TagId = tagId;
        Val = val;
    }

    public byte[] ToByteArray()
        => [Val];

    public static ByteTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
        => new ByteTag(tagId, buffer[0]);
}
