namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls.Enums;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

public class RemoteNetwork
{
    public IPAddress RemoteIP { get; }

    public int Count => _clients.Count;
    private readonly ConcurrentDictionary<IPEndPoint, Client> _clients = new();

    private readonly Settings _settings;
    private readonly ITransport _transport;
    private readonly ClientsService _clientsService;
    private readonly ProjectsService _projectsService;

    public RemoteNetwork(IPAddress remoteIP, Settings settings, ITransport transport, ClientsService clientsService, ProjectsService projectsService)
    {
        RemoteIP = remoteIP;
        _settings = settings;
        _transport = transport;
        _clientsService = clientsService;
        _projectsService = projectsService;
    }

    public Client? GetClient(IPEndPoint endpoint)
        => _clients.GetValueOrDefault(endpoint);

    public bool TryAddClient(IPEndPoint endpoint, out Client? client)
    {
        if (_settings.MaxClientsPerRemoteNetwork <= _clients.Count && !_clients.ContainsKey(endpoint))
        {
            client = null;
            return false;
        }

        client = _clients.GetOrAdd(endpoint, new Client(endpoint, _settings, _transport, _clientsService, _projectsService));
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
        var clients = _clients.Values.Where(x => _settings.MaxInactivitySeconds < Stopwatch.GetElapsedTime(x.LastActivity).TotalSeconds);
        foreach (var client in clients)
        {
            await client.SendAlertBufferAsync(EAlertType.CLOSE_NOTIFY, ct);
            _clientsService.RemoveClient(client.EndPoint);
        }
    }

    public async Task ClearAllClients(CancellationToken ct)
    {
        var clients = _clients.ToArray();
        _clients.Clear();
        foreach (var (endpoint, client) in clients)
        {
            try
            {
                await client.SendAlertBufferAsync(EAlertType.CLOSE_NOTIFY, ct);
            }
            catch { }
            _clientsService.RemoveClient(endpoint);
        }
    }
}
