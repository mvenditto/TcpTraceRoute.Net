using PacketDotNet;
using SharpPcap;
using System.Text.RegularExpressions;

namespace TcpTraceRoute;

public static partial class CaptureDeviceExtensions
{

    [GeneratedRegex("^FriendlyName: (.*)$", RegexOptions.Compiled | RegexOptions.Multiline)]
    private static partial Regex FriendlyNameRegex();

    public static string FriendlyName(this ILiveDevice device)
    {
        var fullInfo = device.ToString();
        if (string.IsNullOrEmpty(fullInfo)) return device.Description;
        var result = FriendlyNameRegex().Match(fullInfo);
        if (result.Success == false) return device.Description;
        return result.Groups[1].Value;
    }
}
