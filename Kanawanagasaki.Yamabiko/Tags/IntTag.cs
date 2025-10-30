namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class IntTag : ITag
{
    public byte TagId { get; }
    private int _val { get; }

    public IntTag(byte tagId, int val)
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
