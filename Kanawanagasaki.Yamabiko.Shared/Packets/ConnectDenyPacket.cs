namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using System;
using System.Text;

public class ConnectDenyPacket : Packet
{
    public const EPacketType TYPE = EPacketType.CONNECT_DENY;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    private byte[] _reasonBytes = Array.Empty<byte>();
    private string? _reason;
    public string? Reason
    {
        get => _reason;
        init
        {
            _reason = value;
            if (value is not null)
                _reasonBytes = Encoding.UTF8.GetBytes(value);
        }
    }

    public ConnectDenyPacket() { }

    private ConnectDenyPacket(byte[] reasonBytes)
    {
        _reasonBytes = reasonBytes;
        if (0 < reasonBytes.Length)
            _reason = Encoding.UTF8.GetString(reasonBytes);
    }

    protected override int InternalLength()
    {
        int len = 0;

        len += 16; // peer id

        len += 1 + _reasonBytes.Length;

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        PeerId.TryWriteBytes(buffer.Slice(offset, 16), true, out _);
        offset += 16;

        buffer[offset++] = (byte)_reasonBytes.Length;
        _reasonBytes.AsSpan(0, (byte)_reasonBytes.Length).CopyTo(buffer.Slice(offset, (byte)_reasonBytes.Length));
    }

    public static ConnectDenyPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        int offset = 0;

        if (buffer.Length < offset + 16)
            throw new FormatException("Buffer too short: cannot read peer id");
        var peerId = new Guid(buffer.Slice(offset, 16), true);
        offset += 16;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too short: cannot read reason length");
        var reasonLength = buffer[offset++];
        if (buffer.Length < offset + reasonLength)
            throw new FormatException("Buffer too short: cannot read reason");
        var reasonSpan = buffer.Slice(offset, reasonLength);

        return new ConnectDenyPacket(reasonSpan.ToArray())
        {
            PeerId = peerId
        };
    }
}
