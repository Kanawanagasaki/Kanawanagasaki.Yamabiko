namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;

public class ByteArrayTag : ITag
{
    public byte TagId { get; }
    private byte[] _val { get; }

    public ByteArrayTag(byte tagId, byte[] val)
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
