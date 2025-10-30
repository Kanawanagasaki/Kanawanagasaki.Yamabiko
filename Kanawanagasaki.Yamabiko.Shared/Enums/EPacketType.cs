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
    EMPTY_QUERY_RESULT = 10,
    EMPTY_QUERY_EXTRA_RESULT = 11,
    PEER = 12,
    PEER_EXTRA = 13,
    CONNECT = 14,
    CONNECT_DENY = 15,
    PEER_CONNECT = 16,
    DIRECT_CONNECT = 17
}
