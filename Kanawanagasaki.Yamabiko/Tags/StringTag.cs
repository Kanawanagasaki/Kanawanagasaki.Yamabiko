namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class StringTag : ITag
{
    public byte TagId { get; }
    public string Val { get; }

    public StringTag(byte tagId, string val)
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

    public static StringTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
    {
        int offset = 0;
        var val = BinaryHelper.ReadString(buffer, ref offset);
        return new StringTag(tagId, val ?? string.Empty);
    }
}
