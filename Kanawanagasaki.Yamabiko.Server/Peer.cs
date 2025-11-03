namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Collections.Concurrent;

public class Peer
{
    public Project Project { get; }

    public Client Client { get; }

    public string Name { get; set; } = string.Empty;

    public string? Password { get; set; }

    public ulong Flags { get; set; } = 0;

    private ConcurrentDictionary<byte, byte[]> _tags = [];
    public IReadOnlyDictionary<byte, byte[]> Tags => _tags.AsReadOnly();

    public Peer(Project project, Client client)
    {
        Client = client;
        Project = project;
    }

    public void AddExtra(byte tag, byte[] data)
        => _tags.AddOrUpdate(tag, data, (_, _) => data);

    public byte[]? GetExtra(byte tag)
        => _tags.GetValueOrDefault(tag);

    public void RemoveExtra(byte tag)
        => _tags.TryRemove(tag, out _);

    public PeerPacket ToPacket(Guid requestId, int index, int total)
        => new PeerPacket
        {
            ProjectId = Project.ProjectId,
            PeerId = Client.PeerId,
            Name = Name,
            Flags = Flags,
            ExtraTags = _tags.Keys.ToArray(),
            ProtectionLevel = Password is null ? EProtectionLevel.PUBLIC : EProtectionLevel.PASSWORD_PROTECTED,
            RequestId = requestId,
            Index = index,
            Total = total
        };
}
