namespace Kanawanagasaki.Yamabiko.Server;
public class ReceiverService
{
    private readonly ClientsService _clientsService;
    private readonly ITransport _transport;

    public ReceiverService(ClientsService clientsService, ITransport transport)
    {
        _clientsService = clientsService;        _transport = transport;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            try
            {
                var result = await _transport.ReceiveAsync(ct);
                await _clientsService.ProcessBufferAsync(result.RemoteEndPoint, result.Buffer, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception e)
            {
                Console.Error.WriteLine($"[System] {e.GetType().Name} | {e.Message}");
            }
        }

        await _clientsService.ClearAllClients(ct);
    }
}
