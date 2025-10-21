namespace Kanawanagasaki.Yamabiko.Server;

using Kanawanagasaki.Yamabiko.Dtls;
using Kanawanagasaki.Yamabiko.Dtls.Enums;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;

public static class UdpService
{
    private static UdpClient? _udp;

    public static async Task RunAsync(CancellationToken ct)
    {
        _udp = new UdpClient(Settings.Port);

        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _udp.ReceiveAsync(ct);
                await ClientsService.ProcessBufferAsync(result.RemoteEndPoint, result.Buffer, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception e)
            {
                Console.Error.WriteLine(e.Message);
            }
        }

        await ClientsService.ClearAllClients(ct);

        _udp.Dispose();
        _udp = null;
    }

    public static async Task SendPacketAsync(IPEndPoint endpoint, ReadOnlyMemory<byte> buffer, CancellationToken ct)
    {
        if (_udp is not null)
            await _udp.SendAsync(buffer, endpoint, ct);
    }
}
