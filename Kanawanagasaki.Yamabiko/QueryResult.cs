﻿namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Shared.Packets;
using System.Collections.Concurrent;
using System.Threading.Channels;

public class QueryResult
{
    public IReadOnlyDictionary<Guid, QueryPeerResult> Peers => _peers.AsReadOnly();

    public Guid RequestId { get; }
    public int Skip { get; }
    public int Count { get; private set; }
    public int Total { get; private set; }
    private readonly ConcurrentDictionary<Guid, QueryPeerResult> _peers;

    private readonly Channel<Packet> _channel;

    public QueryResult(QueryPacket query)
    {
        RequestId = query.RequestId;
        Skip = query.Skip;
        Count = query.Count;
        Total = query.Count;

        _peers = new();

        _channel = Channel.CreateBounded<Packet>(new BoundedChannelOptions(16)
        {
            FullMode = BoundedChannelFullMode.DropOldest
        });
    }

    public IReadOnlySet<int> GetMissingIndices()
    {
        var range = Enumerable.Range(Skip, Count).ToHashSet();
        foreach (var queryPeer in _peers.Values)
            range.Remove(queryPeer.Index);
        return range;
    }

    public IReadOnlyDictionary<Guid, IReadOnlySet<byte>> GetMissingTags()
    {
        var ret = new Dictionary<Guid, IReadOnlySet<byte>>();
        foreach (var queryPeer in _peers.Values)
            if (0 < queryPeer.MissingTags.Count)
                ret[queryPeer.PeerId] = queryPeer.MissingTags;
        return ret;
    }

    public void ProcessEmptyQueryPacket(EmptyQueryResultPacket emptyQuery)
    {
        Total = emptyQuery.Total;
        if (Total < Skip + Count)
            Count = Total - Skip;

        _channel.Writer.TryWrite(emptyQuery);
    }

    public void ProcessEmptyQueryExtraPacket(EmptyQueryExtraResultPacket emptyQueryExtra)
    {
        if(_peers.TryGetValue(emptyQueryExtra.PeerId, out var peer))
            foreach(var tagId in emptyQueryExtra.TagsIds)
                peer.ClearTag(tagId);

        _channel.Writer.TryWrite(emptyQueryExtra);
    }

    public void ProcessPeerPacket(PeerPacket peer)
    {
        var queryPeer = new QueryPeerResult(peer);
        _peers.AddOrUpdate(peer.PeerId, queryPeer, (_, existing) =>
        {
            var newTags = peer.ExtraTags.Order();
            var existingTags = existing.Tags.Keys.Order();
            if (Enumerable.SequenceEqual(newTags, existingTags))
                return existing;
            else
                return queryPeer;
        });

        Total = peer.Total;
        if (Total < Skip + Count)
            Count = Total - Skip;

        _channel.Writer.TryWrite(peer);
    }

    public void ProcessPeerExtraPacket(PeerExtraPacket peerExtra)
    {
        if (_peers.TryGetValue(peerExtra.PeerId, out var queryPeer))
        {
            if(peerExtra.Data is null)
                queryPeer.ClearTag(peerExtra.Tag);
            else
                queryPeer.SetTag(peerExtra.Tag, peerExtra.Data);
        }

        _channel.Writer.TryWrite(peerExtra);
    }

    public async Task<Packet?> AwaitNextPacketAsync(CancellationToken ct)
    {
        if (IsCompleted())
            return null;

        return await _channel.Reader.ReadAsync(ct);
    }

    public bool IsCompleted()
    {
        var isCompleted = _peers.Count == Count && _peers.Values.All(x => x.MissingTags.Count == 0);
        if (isCompleted)
            _channel.Writer.TryComplete();
        return isCompleted;
    }
}
