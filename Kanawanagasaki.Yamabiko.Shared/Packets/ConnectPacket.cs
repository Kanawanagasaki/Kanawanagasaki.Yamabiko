namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using Kanawanagasaki.Yamabiko.Shared.Helpers;
using System;

public class ConnectPacket : Packet
{
    public const EPacketType TYPE = EPacketType.CONNECT;
    public override EPacketType Type => TYPE;

    public required Guid PeerId { get; init; }

    public required uint ConnectionId { get; init; }

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

    private byte[] _publicKey = Array.Empty<byte>();
    public required byte[] PublicKey
    {
        get => _publicKey;
        init
        {
            if (value.Length != 32)
                throw new FormatException("Public key must be 32 bytes long");
            _publicKey = value;
        }
    }

    public byte[]? Extra { get; init; }

    protected override int InternalLength()
    {
        int len = 0;

        len += BinaryHelper.BytesCount(PeerId);

        len += BinaryHelper.BytesCount(ConnectionId);

        len += BinaryHelper.BytesCount(Password);

        len += BinaryHelper.BytesCount(PublicKey);

        len += BinaryHelper.BytesCount(Extra);

        return len;
    }

    protected override void InternalWrite(Span<byte> buffer)
    {
        int offset = 0;

        BinaryHelper.Write(PeerId, buffer, ref offset);

        BinaryHelper.Write(ConnectionId, buffer, ref offset);

        BinaryHelper.Write(Password, buffer, ref offset);

        BinaryHelper.Write(PublicKey, buffer, ref offset);

        BinaryHelper.Write(Extra, buffer, ref offset);
    }

    public static ConnectPacket InternalParse(ReadOnlySpan<byte> buffer)
    {
        try
        {
            int offset = 0;

            var peerId = BinaryHelper.ReadGuid(buffer, ref offset);

            var connectionId = BinaryHelper.ReadUInt32(buffer, ref offset);

            var password = BinaryHelper.ReadString(buffer, ref offset);

            var publicKey = BinaryHelper.ReadByteArray(buffer, ref offset);

            var extra = BinaryHelper.ReadByteArray(buffer, ref offset);

            return new ConnectPacket
            {
                PeerId = peerId,
                ConnectionId = connectionId,
                Password = password,
                PublicKey = publicKey ?? Array.Empty<byte>(),
                Extra = extra
            };
        }
        catch
        {
            throw new FormatException("Failed to parse " + nameof(ConnectPacket));
        }
    }
}
