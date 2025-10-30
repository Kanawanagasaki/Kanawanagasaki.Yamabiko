namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class ShortTag : ITag
{
    public byte TagId { get; }
    private short _val { get; }

    public ShortTag(byte tagId, short val)
    {
        TagId = tagId;
        _val = val;
    }

    public byte[] ToByteArray()
    {
        int offset = 0;
        var buffer = new byte[BinaryHelper.BytesCount(_val)];
        BinaryHelper.Write(_val, buffer, ref offset);
        return buffer;
    }
}
