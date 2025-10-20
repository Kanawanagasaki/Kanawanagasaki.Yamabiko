namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;
using System.Text;

public class AdvertisePacket : Packet
{
    public const EPacketType TYPE = EPacketType.ADVERTISE;
    public override EPacketType Type => TYPE;

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

    private string? _password;
    public string? Password
    {
        get => _password;
        init
        {
            if (value is not null && 255 < BinaryHelper.BytesCount(value))
                throw new FormatException("Password is too long");
            _password = value;
        }
    }

    public ulong Flags { get; init; }

    protected override int InternalLength()
    {
        var len = 0;

        len += BinaryHelper.BytesCount(ProjectId);

        len += BinaryHelper.BytesCount(Name);

        len += BinaryHelper.BytesCount(Password);

        len += BinaryHelper.BytesCount(Flags);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(ProjectId, buffer, ref offset);

        BinaryHelper.Write(Name, buffer, ref offset);

        BinaryHelper.Write(Password, buffer, ref offset);

        BinaryHelper.Write(Flags, buffer, ref offset);
    }

    public static AdvertisePacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var projectId = BinaryHelper.ReadGuid(buffer, ref offset);
            var name = BinaryHelper.ReadString(buffer, ref offset);
            var password = BinaryHelper.ReadString(buffer, ref offset);
            var flags = BinaryHelper.ReadUInt64(buffer, ref offset);

            return new AdvertisePacket
            {
                ProjectId = projectId,
                Name = name ?? string.Empty,
                Password = password,
                Flags = flags
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(AdvertisePacket));
        }
    }
}
