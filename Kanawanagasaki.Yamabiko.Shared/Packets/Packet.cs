namespace Kanawanagasaki.Yamabiko.Shared.Packets;

using Kanawanagasaki.Yamabiko.Shared.Enums;
using System;

public abstract class Packet
{
    public int Length()
        => 4 + InternalLength();

    public void Write(Span<byte> buffer)
    {
        if (buffer.Length < Length())
            throw new ArgumentException("Buffer too small", nameof(buffer));

        buffer[0] = (byte)(((ushort)Type >> 8) & 0xFF);
        buffer[1] = (byte)((ushort)Type & 0xFF);

        var length = InternalLength();
        buffer[2] = (byte)((length >> 8) & 0xFF);
        buffer[3] = (byte)(length & 0xFF);

        InternalWrite(buffer.Slice(4, length));
    }

    public byte[] ToByteArray()
    {
        var buffer = new byte[Length()];
        Write(buffer);
        return buffer;
    }

    public abstract EPacketType Type { get; }
    protected abstract int InternalLength();
    protected abstract void InternalWrite(Span<byte> buffer);

    public static Packet Parse(ReadOnlySpan<byte> buffer)
    {
        if (buffer.Length < 4)
            throw new FormatException("Buffer too small: cannot read packet type and length");

        var packetType = (EPacketType)((buffer[0] << 8) | buffer[1]);
        var length = (buffer[2] << 8) | buffer[3];

        if (buffer.Length < 4 + length)
            throw new FormatException("Buffer too small: cannot read packet data");

        switch (packetType)
        {
            case EPacketType.PING:
                return PingPacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.PONG:
                return PongPacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.SUBSCRIBE:
                return SubscribePacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.UNSUBSCRIBE:
                return UnsubscribePacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.ADVERTISE:
                return AdvertisePacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.STOP_ADVERTISING:
                return StopAdvertisingPacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.QUERY:
                return QueryPacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.PEER:
                return PeerPacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.CONNECT:
                return ConnectPacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.CONNECT_DENY:
                return ConnectDenyPacket.InternalParse(buffer.Slice(4, length));
            case EPacketType.PEER_CONNECT:
                return PeerConnectPacket.InternalParse(buffer.Slice(4, length));
            default:
                throw new FormatException("Unknown packet type");
        }
    }
}
