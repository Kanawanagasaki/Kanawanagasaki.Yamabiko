namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class FloatTag : ITag
{
    public byte TagId { get; }
    public float Val { get; }

    public FloatTag(byte tagId, float val)
    {
        TagId = tagId;
        Val = val;
    }

    public byte[] ToByteArray()
    {
        int offset = 0;
        var buffer = new byte[BinaryHelper.BytesCount(Val)];
        BinaryHelper.Write(Val, buffer, ref offset);
        return buffer;
    }

    public static FloatTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
    {
        int offset = 0;
        var val = BinaryHelper.ReadSingle(buffer, ref offset);
        return new FloatTag(tagId, val);
    }
}
