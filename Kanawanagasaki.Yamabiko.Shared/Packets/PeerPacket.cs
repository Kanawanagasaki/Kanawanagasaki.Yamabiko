namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using System;
using System.Text;

public class PeerPacket : Packet
{
    public const EPacketType TYPE = EPacketType.PEER;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    public required Guid ProjectId { get; init; }

    private byte[] _nameBytes = Array.Empty<byte>();
    private string? _name;
    public string? Name
    {
        get => _name;
        init
        {
            _name = value;
            if (value is not null)
                _nameBytes = Encoding.UTF8.GetBytes(value);
        }
    }

    public byte[] Extra { get; init; } = Array.Empty<byte>();

    public ulong Flags { get; init; }

    public required ushort Index { get; init; }

    public PeerPacket() { }

    private PeerPacket(byte[] nameBytes, byte[] extraBytes)
    {
        _nameBytes = nameBytes;
        if (0 < nameBytes.Length)
            _name = Encoding.UTF8.GetString(nameBytes);

        Extra = extraBytes;
    }

    protected override int InternalLength()
    {
        int len = 0;

        len += 16; // peer id

        len += 16; // project id

        len += 1 + _nameBytes.Length;

        len += 1 + Extra.Length;

        len += 8; // flags

        len += 2; // index

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        PeerId.TryWriteBytes(buffer.Slice(offset, 16), true, out _);
        offset += 16;

        ProjectId.TryWriteBytes(buffer.Slice(offset, 16), true, out _);
        offset += 16;

        buffer[offset++] = (byte)_nameBytes.Length;
        _nameBytes.CopyTo(buffer.Slice(offset, (byte)_nameBytes.Length));
        offset += (byte)_nameBytes.Length;

        buffer[offset++] = (byte)Extra.Length;
        Extra.CopyTo(buffer.Slice(offset, (byte)Extra.Length));
        offset += (byte)Extra.Length;

        buffer[offset++] = (byte)((Flags >> 56) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 48) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 40) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 32) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 24) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 16) & 0xFF);
        buffer[offset++] = (byte)((Flags >> 8) & 0xFF);
        buffer[offset++] = (byte)(Flags & 0xFF);

        buffer[offset++] = (byte)((Index >> 8) & 0xFF);
        buffer[offset++] = (byte)(Index & 0xFF);
    }

    public static PeerPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        int offset = 0;

        if (buffer.Length < offset + 16)
            throw new FormatException("Buffer too small: cannot read peer id");

        var peerId = new Guid(buffer.Slice(offset, 16), true);
        offset += 16;

        if (buffer.Length < offset + 16)
            throw new FormatException("Buffer too small: cannot read project ID");

        var projectId = new Guid(buffer.Slice(offset, 16), true);
        offset += 16;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read name length");
        var nameLength = buffer[offset++];
        if (buffer.Length < offset + nameLength)
            throw new FormatException("Buffer too small: cannot read name");
        var nameSpan = buffer.Slice(offset, nameLength);
        offset += nameLength;

        if (buffer.Length < offset + 1)
            throw new FormatException("Buffer too small: cannot read extra length");
        var extraLength = buffer[offset++];
        if (buffer.Length < offset + extraLength)
            throw new FormatException("Buffer too small: cannot read extra");
        var extraSpan = buffer.Slice(offset, extraLength);
        offset += extraLength;

        if (buffer.Length < offset + 8)
            throw new FormatException("Buffer too small: cannot read flags");
        var flags = ((ulong)buffer[offset++] << 56)
                  | ((ulong)buffer[offset++] << 48)
                  | ((ulong)buffer[offset++] << 40)
                  | ((ulong)buffer[offset++] << 32)
                  | ((ulong)buffer[offset++] << 24)
                  | ((ulong)buffer[offset++] << 16)
                  | ((ulong)buffer[offset++] << 8)
                  | buffer[offset++];

        if (buffer.Length < offset + 2)
            throw new FormatException("Buffer too small: cannot read index");
        var index = (ushort)((buffer[offset++] << 8) | buffer[offset++]);

        return new PeerPacket(nameSpan.ToArray(), extraSpan.ToArray())
        {
            PeerId = peerId,
            ProjectId = projectId,
            Flags = flags,
            Index = index
        };
    }
}
