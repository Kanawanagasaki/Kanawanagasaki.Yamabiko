namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

public class ClientsService
{
    private readonly ConcurrentDictionary<Guid, Client> _clients = new();
    private readonly ConcurrentDictionary<IPAddress, RemoteNetwork> _remoteNetworks = new();

    private readonly Settings _settings;
    private readonly ITransport _transport;
    private readonly ProjectsService _projectsService;

    public ClientsService(Settings settings, ITransport transport, ProjectsService projectsService)
    {
        _settings = settings;
        _transport = transport;
        _projectsService = projectsService;
    }

    public Client? GetClientById(Guid id)
        => _clients.GetValueOrDefault(id);

    public Client? GetClientByEndpoint(IPAddress ip, ushort port)
        => GetClientByEndpoint(new IPEndPoint(ip, port));
    public Client? GetClientByEndpoint(IPEndPoint endpoint)
        => _remoteNetworks.GetValueOrDefault(endpoint.Address)?.GetClient(endpoint);

    public async Task ProcessBufferAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        var network = _remoteNetworks.GetOrAdd(endpoint.Address, new RemoteNetwork(endpoint.Address, _settings, _transport, this, _projectsService));
        var client = network.GetClient(endpoint);

        if (client is null)
        {
            if (_settings.MaxClients <= _clients.Count)
            {
                var alert = new Alert(EAlertType.ACCESS_DENIED);
                var alertBuffer = new byte[alert.Length()];
                alert.Write(alertBuffer);

                var record = new PlainTextRecord(alertBuffer)
                {
                    Type = ERecordType.ALERT,
                    Epoch = 0,
                    RecordNumber = 0
                };
                var recordBuffer = new byte[record.Length()];
                record.Write(recordBuffer);

                await _transport.SendAsync(endpoint, buffer, ct);
                return;
            }
            else if (!network.TryAddClient(endpoint, out client))
            {
                var alert = new Alert(EAlertType.ACCESS_DENIED);
                var alertBuffer = new byte[alert.Length()];
                alert.Write(alertBuffer);

                var record = new PlainTextRecord(alertBuffer)
                {
                    Type = ERecordType.ALERT,
                    Epoch = 0,
                    RecordNumber = 0
                };
                var recordBuffer = new byte[record.Length()];
                record.Write(recordBuffer);

                await _transport.SendAsync(endpoint, buffer, ct);
                return;
            }

            if (client is not null)
                _clients.AddOrUpdate(client.PeerId, client, (_, _) => client);
        }

        if (client is not null)
            await client.ProcessBufferAsync(buffer, ct);
    }

    public void RemoveClient(IPEndPoint endpoint)
    {
        if (_remoteNetworks.TryGetValue(endpoint.Address, out var network))
        {
            var client = network.RemoveClient(endpoint);
            if (client is not null)
            {
                _projectsService.RemovePeer(client.PeerId);

                _clients.TryRemove(client.PeerId, out _);
                client.Dispose();
            }

            if (network.Count == 0)
                _remoteNetworks.TryRemove(network.RemoteIP, out _);
        }
    }

    public async Task RunClearTimerAsync(CancellationToken ct)
    {
        var timer = new PeriodicTimer(TimeSpan.FromSeconds(_settings.MaxInactivitySeconds / 2d));
        while (await timer.WaitForNextTickAsync(ct) && !ct.IsCancellationRequested)
        {
            try
            {
                foreach (var network in _remoteNetworks.Values)
                {
                    await network.ClearInactiveClientsAsync(ct);

                    if (network.Count == 0)
                        _remoteNetworks.TryRemove(network.RemoteIP, out _);
                }

                await timer.WaitForNextTickAsync(ct);

                foreach (var client in _clients.Values)
                {
                    if (_settings.MaxInactivitySeconds < Stopwatch.GetElapsedTime(client.LastActivity).TotalSeconds)
                        RemoveClient(client.EndPoint);
                }
            }
            catch (OperationCanceledException) { }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
        }
    }

    public async Task ClearAllClients(CancellationToken ct)
    {
        foreach (var network in _remoteNetworks.Values)
        {
            await network.ClearAllClients(ct);

            if (network.Count == 0)
                _remoteNetworks.TryRemove(network.RemoteIP, out _);
        }

        foreach (var client in _clients.Values)
        {
            if (_settings.MaxInactivitySeconds < Stopwatch.GetElapsedTime(client.LastActivity).TotalSeconds)
                RemoveClient(client.EndPoint);
        }
    }
}
