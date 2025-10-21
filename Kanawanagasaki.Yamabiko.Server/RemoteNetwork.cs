namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

public class RemoteNetwork
{
    public IPAddress RemoteIP { get; }

    public int Count => _clients.Count;
    private ConcurrentDictionary<IPEndPoint, Client> _clients = new();

    public RemoteNetwork(IPAddress remoteIP)
    {
        RemoteIP = remoteIP;
    }

    public Client? GetClient(IPEndPoint endpoint)
        => _clients.GetValueOrDefault(endpoint);

    public bool TryAddClient(IPEndPoint endpoint, out Client? client)
    {
        if (Settings.MaxClientsPerRemoteNetwork <= _clients.Count && !_clients.ContainsKey(endpoint))
        {
            client = null;
            return false;
        }

        client = _clients.GetOrAdd(endpoint, new Client(endpoint));
        return true;
    }

    public Client? RemoveClient(IPEndPoint endpoint)
    {
        if (_clients.TryRemove(endpoint, out var client))
            return client;
        return null;
    }

    public async Task ClearInactiveClientsAsync(CancellationToken ct)
    {
        var clients = _clients.Values.Where(x => Settings.MaxInactivitySeconds < Stopwatch.GetElapsedTime(x.LastActivity).TotalSeconds);
        foreach (var client in clients)
        {
            await client.SendAlertBufferAsync(EAlertType.CLOSE_NOTIFY, ct);
            ClientsService.RemoveClient(client.EndPoint);
        }
    }

    public async Task ClearAllClients(CancellationToken ct)
    {
        var clients = _clients.ToArray();
        _clients.Clear();
        foreach (var (endpoint, client) in clients)
        {
            await client.SendAlertBufferAsync(EAlertType.CLOSE_NOTIFY, ct);
            ClientsService.RemoveClient(endpoint);
        }
    }
}
