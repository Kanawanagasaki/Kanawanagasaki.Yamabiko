namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;
using System.Text;

public class PeerPacket : Packet
{
    public const EPacketType TYPE = EPacketType.PEER;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    public required Guid ProjectId { get; init; }

    private string _name = string.Empty;
    public string Name
    {
        get => _name;
        init
        {
            if (255 < BinaryHelper.BytesCount(value))
                throw new FormatException("Name is too long");
            _name = value;
        }
    }

    public ulong Flags { get; init; }

    public byte[] _extraTags = Array.Empty<byte>();
    public byte[] ExtraTags
    {
        get => _extraTags;
        init
        {
            if (255 < value.Length)
                throw new FormatException("Extra Tags is too long");
            _extraTags = value;
        }
    }

    public required EProtectionLevel ProtectionLevel { get; init; }

    public required Guid RequestId { get; init; }

    public required int Index { get; init; }

    public required int Total { get; init; }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(PeerId);

        len += BinaryHelper.BytesCount(ProjectId);

        len += BinaryHelper.BytesCount(Name);

        len += BinaryHelper.BytesCount(Flags);

        len += BinaryHelper.BytesCount(ExtraTags);

        len += 1; // Protection Level

        len += BinaryHelper.BytesCount(RequestId);

        len += BinaryHelper.BytesCount(Index);

        len += BinaryHelper.BytesCount(Total);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(PeerId, buffer, ref offset);

        BinaryHelper.Write(ProjectId, buffer, ref offset);

        BinaryHelper.Write(Name, buffer, ref offset);

        BinaryHelper.Write(Flags, buffer, ref offset);

        BinaryHelper.Write(ExtraTags, buffer, ref offset);

        buffer[offset++] = (byte)ProtectionLevel;

        BinaryHelper.Write(RequestId, buffer, ref offset);

        BinaryHelper.Write(Index, buffer, ref offset);

        BinaryHelper.Write(Total, buffer, ref offset);
    }

    public static PeerPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var peerId = BinaryHelper.ReadGuid(buffer, ref offset);

            var projectId = BinaryHelper.ReadGuid(buffer, ref offset);

            var name = BinaryHelper.ReadString(buffer, ref offset);

            var flags = BinaryHelper.ReadUInt64(buffer, ref offset);

            var extraTags = BinaryHelper.ReadByteArray(buffer, ref offset);

            var protectionLevel = (EProtectionLevel)buffer[offset++];

            var requestId = BinaryHelper.ReadGuid(buffer, ref offset);

            var index = BinaryHelper.ReadInt32(buffer, ref offset);

            var total = BinaryHelper.ReadInt32(buffer, ref offset);

            return new PeerPacket
            {
                PeerId = peerId,
                ProjectId = projectId,
                Name = name ?? string.Empty,
                Flags = flags,
                ExtraTags = extraTags ?? Array.Empty<byte>(),
                ProtectionLevel = protectionLevel,
                RequestId = requestId,
                Index = index,
                Total = total
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(PeerPacket));
        }
    }
}
