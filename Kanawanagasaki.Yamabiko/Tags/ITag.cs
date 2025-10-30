namespace Kanawanagasaki.Yamabiko.Tags;

public interface ITag
{
    byte TagId { get; }
    byte[] ToByteArray();
}
