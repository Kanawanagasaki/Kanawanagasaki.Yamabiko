namespace Kanawanagasaki.Yamabiko.Server;
public class ReceiveService
{
    private readonly ClientsService _clientsService;
    private readonly ITransport _transport;

    public ReceiveService(ClientsService clientsService, ITransport transport)
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
                Console.Error.WriteLine(e.Message);
            }
        }

        await _clientsService.ClearAllClients(ct);
    }
}
