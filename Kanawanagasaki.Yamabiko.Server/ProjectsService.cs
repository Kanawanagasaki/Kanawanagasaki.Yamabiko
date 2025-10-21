namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Collections.Concurrent;

public static class ProjectsService
{
    private static readonly ConcurrentDictionary<Guid, Project> _projects = [];
    private static readonly ConcurrentDictionary<Guid, Project> _peerIdToProject = [];

    public static Peer? GetPeer(Guid peerId)
        => _peerIdToProject.GetValueOrDefault(peerId)?.GetPeer(peerId);

    public static Project? GetProject(Guid projectId)
        => _projects.GetValueOrDefault(projectId);

    public static Peer ProcessAdvertisement(Client client, AdvertisePacket ad)
    {
        if (_peerIdToProject.TryGetValue(client.PeerId, out var existingProject))
        {
            if (existingProject.ProjectId == ad.ProjectId)
                return existingProject.ProcessAdvertisement(client, ad);

            RemovePeer(client.PeerId);
        }

        var project = _projects.GetOrAdd(ad.ProjectId, new Project(ad.ProjectId));
        _peerIdToProject.TryAdd(client.PeerId, project);

        return project.ProcessAdvertisement(client, ad);
    }

    public static Peer? ProcessAdvertisementExtra(Guid peerId, AdvertiseExtraPacket adExtra)
    {
        if (_peerIdToProject.TryGetValue(peerId, out var project) && project.ProjectId == adExtra.ProjectId)
            return project.ProcessAdvertisementExtra(peerId, adExtra);
        return null;
    }

    public static void ProcessSubscribe(Client client, SubscribePacket subscribe)
    {
        var project = _projects.GetOrAdd(subscribe.ProjectId, new Project(subscribe.ProjectId));
        project.Subscribe(client);
    }

    public static void ProcessUnsubscribe(Guid peerId, UnsubscribePacket unsubscribe)
    {
        if (_projects.TryGetValue(unsubscribe.ProjectId, out var project))
        {
            project.Unsubscribe(peerId);
            if (project.Count == 0 && project.SubscribersCount == 0)
                _projects.TryRemove(project.ProjectId, out _);
        }
    }

    public static void RemovePeer(Guid peerId)
    {
        if (_peerIdToProject.TryRemove(peerId, out var project))
        {
            project.RemovePeer(peerId);
            if (project.Count == 0 && project.SubscribersCount == 0)
                _projects.TryRemove(project.ProjectId, out _);
        }
    }
}
