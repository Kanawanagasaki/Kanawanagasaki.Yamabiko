namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Tags;

public class Advertisement
{
    public string Name { get; init; } = string.Empty;
    public string? Password { get; init; }
    public ulong Flags { get; init; }
    public IEnumerable<ITag>? Tags { get; init; }
}
