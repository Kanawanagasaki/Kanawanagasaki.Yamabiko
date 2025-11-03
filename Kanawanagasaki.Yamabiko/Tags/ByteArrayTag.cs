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
    {
        int offset = 0;
        var buffer = new byte[BinaryHelper.BytesCount(Val)];
        BinaryHelper.Write(Val, buffer, ref offset);
        return buffer;
    }

    public static ByteArrayTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
    {
        int offset = 0;
        var val = BinaryHelper.ReadByteArray(buffer, ref offset);
        return new ByteArrayTag(tagId, val ?? Array.Empty<byte>());
    }
}
