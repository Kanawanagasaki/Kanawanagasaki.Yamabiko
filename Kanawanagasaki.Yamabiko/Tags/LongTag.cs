namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class LongTag : ITag
{
    public byte TagId { get; }
    public long Val { get; }

    public LongTag(byte tagId, long val)
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

    public static LongTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
    {
        int offset = 0;
        var val = BinaryHelper.ReadInt64(buffer, ref offset);
        return new LongTag(tagId, val);
    }
}
