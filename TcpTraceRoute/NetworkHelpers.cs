using SharpPcap;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

namespace TcpTraceRoute.Helpers;

public static class NetworkHelpers
{
    /// <summary>
    /// Tries to Determines the source address that should be used to reach the given destination address.
    /// </summary>
    /// <param name="remoteAddress">the destinatio IP address</param>
    /// <returns>the local IP address, if available</returns>
    public static async Task<IPAddress?> FindSourceAddress(IPAddress remoteAddress)
    {
        ArgumentNullException.ThrowIfNull(remoteAddress);

        using var socket = new Socket(
            AddressFamily.InterNetwork, 
            SocketType.Dgram, 
            ProtocolType.Udp);

        var remoteEndpoint = new IPEndPoint(remoteAddress, 53);

        await socket.ConnectAsync(remoteEndpoint);

        var localEndPoint = socket.LocalEndPoint as IPEndPoint;

        return localEndPoint?.Address;
    }

    public static (ILiveDevice?, NetworkInterface?) FindDevice(IPAddress srcAddress)
    {
        ArgumentNullException.ThrowIfNull(srcAddress);

        var devices = CaptureDeviceList.Instance;

        if (devices.Count < 1)
        {
            throw new InvalidOperationException("No devices were found on this machine");
        }

        var interfaces = NetworkInterface.GetAllNetworkInterfaces();

        NetworkInterface nic = null;

        foreach (var iface in interfaces)
        {
            if (iface.OperationalStatus != OperationalStatus.Up)
            {
                continue;
            }

            var ifaceType = iface.NetworkInterfaceType;

            if (ifaceType != NetworkInterfaceType.Ethernet && 
                ifaceType != NetworkInterfaceType.Wireless80211)
            {
                continue;
            }

            var ipProps = iface.GetIPProperties();

            if (ipProps == null)
            {
                continue;
            }

            var ipAddresses = ipProps.UnicastAddresses
                .Where(a => a.Address.AddressFamily == AddressFamily.InterNetwork);

            if (ipAddresses.Any(ip => ip.Address.Equals(srcAddress)))
            {
                nic = iface;
                break;
            }
        }

        if (nic == null)
        {
            return (null, null);
        }

        var device = devices
            .Where(d => d.MacAddress != null)
            .Single(x => x.MacAddress.Equals(nic.GetPhysicalAddress()));

        return (device, nic);
    }

    public static ushort AllocatePort(ushort requestSrcPort)
    {
        ArgumentNullException.ThrowIfNull(requestSrcPort);

        using var socket = new Socket(
            AddressFamily.InterNetwork,
            SocketType.Stream,
            ProtocolType.Tcp);

        try
        {
            socket.Bind(new IPEndPoint(IPAddress.Loopback, requestSrcPort));
        }
        catch (SocketException e)
        {
            return 0;
        }

        var localEndpoint = socket.LocalEndPoint as IPEndPoint;

        return (ushort)localEndpoint.Port;
    }
}
