namespace Kanawanagasaki.Yamabiko.Tags;

using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System.Text;

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
        => Encoding.UTF8.GetBytes(Val);

    public static StringTag Parse(byte tagId, ReadOnlySpan<byte> buffer)
        => new StringTag(tagId, Encoding.UTF8.GetString(buffer));
}
