namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Shared.Packets;

public class QueryPeerResult
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

    public QueryPeerResult(PeerPacket peer)
    {
        PeerId = peer.PeerId;
        ProjectId = peer.ProjectId;
        Name = peer.Name;
        Flags = peer.Flags;
        Index = peer.Index;

        _missingTags = new HashSet<byte>(peer.ExtraTags);
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
}
