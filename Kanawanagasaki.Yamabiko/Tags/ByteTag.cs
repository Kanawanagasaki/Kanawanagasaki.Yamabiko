namespace Kanawanagasaki.Yamabiko.Tags;

public class ByteTag : ITag
{
    public byte TagId { get; }
    private byte _val { get; }

    public ByteTag(byte tagId, byte val)
    {
        TagId = tagId;
        _val = val;
    }

    public byte[] ToByteArray()
        => [_val];
}
