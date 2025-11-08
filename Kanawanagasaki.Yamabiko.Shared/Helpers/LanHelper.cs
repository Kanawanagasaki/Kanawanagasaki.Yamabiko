namespace Kanawanagasaki.Yamabiko.Shared.Helpers;

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

public static class LanHelper
{
    public static IPAddress? GetLanAddress()
        => GetLanAddressViaUdp()
        ?? GetLanAddressViaDns();

    public static IPAddress? GetLanAddressViaDns()
    {
        var host = Dns.GetHostEntry(Dns.GetHostName());
        foreach (var ip in host.AddressList)
            if (ip.AddressFamily == AddressFamily.InterNetwork && !IPAddress.IsLoopback(ip))
                return ip;
        return null;
    }

    public static IPAddress? GetLanAddressViaUdp()
    {
        using var socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, 0);
        socket.Connect("8.8.8.8", 65530);
        var endPoint = socket.LocalEndPoint as IPEndPoint;
        return endPoint?.Address;
    }
}
