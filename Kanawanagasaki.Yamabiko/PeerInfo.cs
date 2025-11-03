namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using Kanawanagasaki.Yamabiko.Tags;

public class PeerInfo
{
    public Guid PeerId { get; }
    public Guid ProjectId { get; }
    public string Name { get; }
    public ulong Flags { get; }
    public int Index { get; }

    private Dictionary<byte, byte[]> _tags = [];
    public IReadOnlyDictionary<byte, byte[]> Tags => _tags;

    private HashSet<byte> _missingTags;
    public IReadOnlySet<byte> MissingTags => _missingTags;

    public PeerInfo(PeerPacket peer)
    {
        PeerId = peer.PeerId;
        ProjectId = peer.ProjectId;
        Name = peer.Name;
        Flags = peer.Flags;
        Index = peer.Index;

        _missingTags = [.. peer.ExtraTags];
    }

    public void SetTag(byte tagId, byte[] tag)
    {
        _tags[tagId] = tag;
        _missingTags.Remove(tagId);
    }

    public void ClearTag(byte tagId)
    {
        _tags.Remove(tagId);
        _missingTags.Remove(tagId);
    }

    public T? GetTag<T>(byte tagId) where T : class, ITag
    {
        if (!_tags.TryGetValue(tagId, out var tagBytes))
            return null;

        return ITag.Parse<T>(tagId, tagBytes);
    }
}
