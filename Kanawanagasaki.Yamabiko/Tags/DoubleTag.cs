namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class DoubleTag : ITag
{
    public byte TagId { get; }
    private double _val { get; }

    public DoubleTag(byte tagId, double val)
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
