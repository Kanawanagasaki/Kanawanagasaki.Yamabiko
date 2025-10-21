namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Net;

public static class ClientsService
{
    private static ConcurrentDictionary<Guid, Client> _clients = new();
    private static ConcurrentDictionary<IPAddress, RemoteNetwork> _remoteNetworks = new();

    public static Client? GetClientById(Guid id)
        => _clients.GetValueOrDefault(id);

    public static Client? GetClientByEndpoint(IPAddress ip, ushort port)
        => GetClientByEndpoint(new IPEndPoint(ip, port));
    public static Client? GetClientByEndpoint(IPEndPoint endpoint)
        => _remoteNetworks.GetValueOrDefault(endpoint.Address)?.GetClient(endpoint);

    public static async Task ProcessBufferAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        var network = _remoteNetworks.GetOrAdd(endpoint.Address, new RemoteNetwork(endpoint.Address));
        var client = network.GetClient(endpoint);

        if (client is null)
        {
            if (Settings.MaxClients <= _clients.Count)
            {
                var alert = new Alert(EAlertType.ACCESS_DENIED);
                var alertBuffer = new byte[alert.Length()];
                alert.Write(alertBuffer);

                var record = new PlainTextRecord(alertBuffer)
                {
                    Type = ERecordType.ALERT,
                    KeyEpoch = 0,
                    RecordNumber = 0
                };
                var recordBuffer = new byte[record.Length()];
                record.Write(recordBuffer);

                await UdpService.SendPacketAsync(endpoint, buffer, ct);
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
                    KeyEpoch = 0,
                    RecordNumber = 0
                };
                var recordBuffer = new byte[record.Length()];
                record.Write(recordBuffer);

                await UdpService.SendPacketAsync(endpoint, buffer, ct);
                return;
            }

            if (client is not null)
                _clients.AddOrUpdate(client.PeerId, client, (_, _) => client);
        }

        if (client is not null)
            await client.ProcessBufferAsync(buffer, ct);
    }

    public static void RemoveClient(IPEndPoint endpoint)
    {
        if (_remoteNetworks.TryGetValue(endpoint.Address, out var network))
        {
            var client = network.RemoveClient(endpoint);
            if (client is not null)
            {
                ProjectsService.RemovePeer(client.PeerId);

                _clients.TryRemove(client.PeerId, out _);
                client.Dispose();
            }

            if (network.Count == 0)
                _remoteNetworks.TryRemove(network.RemoteIP, out _);
        }
    }

    public static async Task RunClearTimerAsync(CancellationToken ct)
    {
        var timer = new PeriodicTimer(TimeSpan.FromSeconds(Settings.MaxInactivitySeconds / 2d));
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
                    if (Settings.MaxInactivitySeconds < Stopwatch.GetElapsedTime(client.LastActivity).TotalSeconds)
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

    public static async Task ClearAllClients(CancellationToken ct)
    {
        foreach (var network in _remoteNetworks.Values)
        {
            await network.ClearAllClients(ct);

            if (network.Count == 0)
                _remoteNetworks.TryRemove(network.RemoteIP, out _);
        }

        foreach (var client in _clients.Values)
        {
            if (Settings.MaxInactivitySeconds < Stopwatch.GetElapsedTime(client.LastActivity).TotalSeconds)
                RemoveClient(client.EndPoint);
        }
    }
}
