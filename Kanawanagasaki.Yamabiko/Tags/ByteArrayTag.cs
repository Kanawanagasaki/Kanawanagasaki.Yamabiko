namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class ByteArrayTag : ITag
{
    public byte TagId { get; }
    public byte[] Val { get; }

    public ByteArrayTag(byte tagId, byte[] val)
    {
        TagId = tagId;
        Val = val;
    }

    public byte[] ToByteArray()
        => Val;

    public static ByteArrayTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
        => new ByteArrayTag(tagId, buffer.ToArray());
}
