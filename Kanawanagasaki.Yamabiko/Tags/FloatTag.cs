namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class FloatTag : ITag
{
    public byte TagId { get; }
    private float _val { get; }

    public FloatTag(byte tagId, float val)
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
