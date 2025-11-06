namespace Kanawanagasaki.Yamabiko.Dtls.Extensions;

using Kanawanagasaki.Yamabiko.Dtls.Enums;

internal class ConnectionIdExtension : IExtension
{
    internal const EExtensionType TYPE = EExtensionType.CONNECTION_ID;
    public EExtensionType Type => TYPE;

    internal byte[] ConnectionId { get; }

    internal ConnectionIdExtension(byte[] connectionId)
    {
        if (byte.MaxValue < connectionId.Length)
            throw new ArgumentException($"Connection ID length exceeds {byte.MaxValue} bytes");

        ConnectionId = connectionId;
    }

    public int Length(bool isRequest)
        => 1 + ConnectionId.Length;

    public void Write(Span<byte> buffer, bool isRequest)
    {
        if (buffer.Length < Length(isRequest))
            throw new ArgumentException("Buffer too small", nameof(buffer));

        buffer[0] = (byte)ConnectionId.Length;
        ConnectionId.CopyTo(buffer[1..]);
    }

    internal static ConnectionIdExtension Parse(Span<byte> buffer, bool isRequest)
    {
        if (buffer.Length < 1)
            throw new FormatException("Buffer too small to read connection ID length");

        var connectionIdLen = buffer[0];
        if (buffer.Length < connectionIdLen + 1)
            throw new FormatException("Buffer too small to read connection ID");

        return new ConnectionIdExtension(buffer.Slice(1, connectionIdLen).ToArray());
    }
}
