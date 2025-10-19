namespace Kanawanagasaki.Yamabiko.Shared.Enums;

public enum EPacketType : ushort
{
    PING = 1,
    PONG = 2,
    SUBSCRIBE = 3,
    UNSUBSCRIBE = 4,
    ADVERTISE = 5,
    STOP_ADVERTISING = 6,
    QUERY = 7,
    PEER = 8,
    CONNECT = 9,
    CONNECT_DENY = 10,
    PEER_CONNECT = 11
}
