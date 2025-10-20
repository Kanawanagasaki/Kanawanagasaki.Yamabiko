namespace Kanawanagasaki.Yamabiko.Shared.Enums;

public enum EPacketType : ushort
{
    PING = 1,
    PONG = 2,
    SUBSCRIBE = 3,
    UNSUBSCRIBE = 4,
    ADVERTISE = 5,
    ADVERTISE_EXTRA = 6,
    STOP_ADVERTISING = 7,
    QUERY = 8,
    QUERY_EXTRA = 9,
    PEER = 10,
    PEER_EXTRA = 11,
    CONNECT = 12,
    CONNECT_DENY = 13,
    PEER_CONNECT = 14,
    DIRECT_CONNECT = 15
}
