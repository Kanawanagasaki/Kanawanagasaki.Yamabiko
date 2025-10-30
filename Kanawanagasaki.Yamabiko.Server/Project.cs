namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls.Helpers;
using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Collections.Concurrent;
using System.Security.Cryptography;

public class Project
{
    private readonly ConcurrentDictionary<Guid, Peer> _peers = [];
    private readonly ConcurrentDictionary<Guid, Client> _subsribers = [];

    public int Count => _peers.Count;
    public int SubscribersCount => _subsribers.Count;

    public Guid ProjectId { get; }

    public Project(Guid projectId)
    {
        ProjectId = projectId;
    }

    public Peer? GetPeer(Guid peerId)
        => _peers.GetValueOrDefault(peerId);

    public void RemovePeer(Guid peerId)
        => _peers.TryRemove(peerId, out _);

    public Peer ProcessAdvertisement(Client client, AdvertisePacket ad)
    {
        var peer = _peers.GetOrAdd(client.PeerId, new Peer(this, client));
        peer.Name = ad.Name;
        peer.Password = ad.Password;
        peer.Flags = ad.Flags;
        return peer;
    }

    public Peer? ProcessAdvertisementExtra(Guid peerId, AdvertiseExtraPacket adExtra)
    {
        var peer = GetPeer(peerId);
        if (peer is null)
            return null;

        if (adExtra.Data is null)
            peer.RemoveExtra(adExtra.Tag);
        else
            peer.AddExtra(adExtra.Tag, adExtra.Data);

        return peer;
    }

    public void Subscribe(Client client)
        => _subsribers.AddOrUpdate(client.PeerId, client, (_, _) => client);

    public void Unsubscribe(Guid peerId)
        => _subsribers.TryRemove(peerId, out _);

    public IEnumerable<Client> GetSubscribers()
        => _subsribers.Values;

    public (int total, IEnumerable<Peer> res) Query(QueryPacket query)
    {
        bool flagsCheck(Peer p) => (p.Flags & query.Flags) == query.Flags;
        bool protectionCheck(Peer p) => query.ProtectionLevel.HasFlag(EProtectionLevel.PASSWORD_PROTECTED) ? p.Password is not null
                                      : query.ProtectionLevel.HasFlag(EProtectionLevel.PUBLIC) ? p.Password is null
                                      : true;
        bool filterCheck(Peer p)
        {
            if (query.Filter is null)
                return true;

            var extra = p.GetExtra(query.FilterTag);
            if (extra is null)
                return false;

            switch (query.FilterOperation)
            {
                case EFilterOperation.LESS:
                    return KeyHashHelper.CompareByteArrayLex(extra, query.Filter) < 0;
                case EFilterOperation.LESS_OR_EQUALS:
                    return KeyHashHelper.CompareByteArrayLex(extra, query.Filter) <= 0;
                case EFilterOperation.EQUALS:
                    return Enumerable.SequenceEqual(query.Filter, extra);
                case EFilterOperation.GREATER_OR_EQUALS:
                    return 0 <= KeyHashHelper.CompareByteArrayLex(extra, query.Filter);
                case EFilterOperation.GREATER:
                    return 0 < KeyHashHelper.CompareByteArrayLex(extra, query.Filter);
                case EFilterOperation.CONTAINS:
                    {
                        if (extra.Length == 0 && query.Filter.Length == 0)
                            return true;
                        if (extra.Length < query.Filter.Length)
                            return false;
                        if (extra.Length == query.Filter.Length)
                            return Enumerable.SequenceEqual(query.Filter, extra);

                        for (int i = 0; i <= extra.Length - query.Filter.Length; i++)
                        {
                            for (int j = 0; j < query.Filter.Length; j++)
                            {
                                if (extra[i + j] != query.Filter[j])
                                    goto skip;
                            }

                            return true;

                        skip:
                            _ = 1;
                        }
                        return false;
                    }
                default:
                    return true;
            }
        }

        var where = _peers.Values.Where(x => flagsCheck(x) && protectionCheck(x) && filterCheck(x));
        var ordered = query.OrderBy switch
        {
            EOrderBy.NAME_ASC => where.OrderBy(x => x.Name),
            EOrderBy.NAME_DESC => where.OrderByDescending(x => x.Name),
            EOrderBy.TIME_DESC => where.OrderByDescending(x => x.Client.PeerId),
            EOrderBy.RANDOM => where.OrderBy(_ => Random.Shared.NextDouble()),
            _ => where.OrderBy(x => x.Client.PeerId)
        };
        var total = ordered.Count();
        var res = ordered.Skip(query.Skip).Take(query.Count);
        return (total, res);
    }
}
