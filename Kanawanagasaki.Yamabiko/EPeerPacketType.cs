namespace Kanawanagasaki.Yamabiko;

public enum EPeerPacketType : byte
{
    PING = 1,
    PONG = 2,
    UNRELIABLE = 10,
    RELIABLE = 11,
    STREAM = 12
}
