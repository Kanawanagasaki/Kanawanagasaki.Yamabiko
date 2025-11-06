namespace Kanawanagasaki.Yamabiko;

using Kanawanagasaki.Yamabiko.Dtls;

internal class AcknowledgeableRecord
{
    internal CipherTextRecord Record { get; }

    private readonly TaskCompletionSource<Ack> _tcs;

    internal AcknowledgeableRecord(CipherTextRecord record)
    {
        Record = record;
        _tcs = new TaskCompletionSource<Ack>(TaskCreationOptions.RunContinuationsAsynchronously);
    }

    internal async Task<Ack> WaitAcknowledgment(TimeSpan timeout, CancellationToken ct = default)
    {
        var delayTask = Task.Delay(timeout, ct);
        var completed = await Task.WhenAny(_tcs.Task, delayTask).ConfigureAwait(false);

        if (completed == _tcs.Task)
        {
            return await _tcs.Task.ConfigureAwait(false);
        }
        else
        {
            ct.ThrowIfCancellationRequested();
            throw new TimeoutException($"Record {Record.RecordNumber} timed out after {timeout}");
        }
    }

    internal void Acknowledge(Ack ack)
    {
        _tcs.TrySetResult(ack);
    }

    internal void Discard()
    {
        _tcs.TrySetException(new TimeoutException($"Record {Record.RecordNumber} was discarded"));
    }
}
