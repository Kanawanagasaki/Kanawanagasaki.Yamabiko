namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class IntTag : ITag
{
    public byte TagId { get; }
    public int Val { get; }

    public IntTag(byte tagId, int val)
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

    public static IntTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
    {
        int offset = 0;
        var val = BinaryHelper.ReadInt32(buffer, ref offset);
        return new IntTag(tagId, val);
    }
}
