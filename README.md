# TcpTraceRoute

A TCP-based traceroute library and tool inspired by the original [tcptraceroute](https://github.com/mct/tcptraceroute) tool.

Built with [packetnet](https://github.com/dotpcap/packetnet) and [sharppcap](https://github.com/dotpcap/sharppcap).

> **Note** behavior may vary from the original tool, and some options are not supported yet (e.g trackport)

## Cli
<details>
<summary>Help</summary>
  
```
Description:

Usage:
  tcptraceroute-net <dst-host> [<dst-port>] [options]

Arguments:
  <dst-host>
  <dst-port>  [default: 80]

Options:
  -d                               debug mode [default: False]
  -n                               do not resolve probe hostname [default: True]
  -q, --num-queries <num-queries>  [default: 3]
  -f, --first-ttl <first-ttl>      [default: 1]
  --track-port                     [default: False]
  -P, --force-port                 [default: False]
  --dnat                           [default: False]
  -i, --interface <interface>
  -l, --packet-len <packet-len>    [default: 0]
  -m, --max-ttl <max-ttl>          [default: 30]
  -t, --tos <tos>                  [default: 0]
  -s, --src-address <src-address>
  -p, --src-port <src-port>        [default: 0]
  -w, --wait-time <wait-time>      packet read timeout (ms) [default: 3000]
  -S                               set SYN tcp flag [default: True]
  -A                               set ACK tcp flag [default: False]
  -E                               set ECN tcp flag [default: False]
  -U                               set URG tcp flag [default: False]
  --version                        Show version information
  -?, -h, --help                   Show help and usage information
```
    
</details>

## Cli - Samples
<details>
<summary>traceroute-net github.com -q 1</summary>
<pre>
 Selected device Wi-Fi (Intel(R) Wi-Fi 6 AX201 160MHz), address 192.168.1.56, port 60563 for outgoing packets
 Tracing the path to github.com (140.82.121.4) on TCP port 80, 30 hops max
 1  home-life.hub      1.411 ms
 2  151.6.142.56       7.518 ms
 3  151.6.57.36        7.175 ms
 4  151.6.6.68         9.696 ms
 5  151.6.7.181        10.650 ms
 6  *                  *
 7  64.125.30.254      26.075 ms
 8  ae1.mcs1.fra9.de.eth.zayo.com    32.603 ms
 9  82.98.193.29.IPYX-270403-002-ZYO.zip.zayo.com    26.751 ms
10  *                  *
11  *                  *
12  lb-140-82-121-4-fra.github.com  [open]  26.199 ms
</pre>
</details>
    
<details>
<summary>traceroute-net github.com -q 3 -n </summary>
<pre>
 Selected device Wi-Fi (Intel(R) Wi-Fi 6 AX201 160MHz), address 192.168.1.56, port 60563 for outgoing packets
 Tracing the path to github.com (140.82.121.3) on TCP port 80, 30 hops max
 1  192.168.1.1        1.873 ms  1.196 ms  1.230 ms
 2  151.6.142.56       6.731 ms  7.207 ms  6.189 ms
 3  151.6.57.36        6.432 ms  6.351 ms  9.545 ms
 4  151.6.6.68         9.502 ms  9.882 ms  9.262 ms
 5  151.6.7.181        10.197 ms  11.756 ms  10.146 ms
 6  80.81.194.26       25.581 ms  25.906 ms  25.646 ms
 7  64.125.30.254      26.460 ms  25.677 ms  25.404 ms
 8  64.125.29.65       31.942 ms  32.211 ms  31.858 ms
 9  82.98.193.29       25.576 ms  25.550 ms  26.520 ms
10  *                  *  *  *
11  *                  *  *  *
12  140.82.121.3     [open]  25.800 ms  25.744 ms  835.491 ms
</pre>
</details>

## Code
```csharp
var dstAddress = IPAddress.Parse("8.8.8.8");

var srcAddress = await NetworkHelpers.FindSourceAddress(dstAddress);

var (device, networkInterface) = NetworkHelpers.FindDevice(sourceAddress);

var options = new TcpTraceRouteOptions
{
    TcpDestinationPort = 80,
    NumQueries = 3,
    MaxTtl = 30,
    Timeout = TimeSpan.FromMilliseconds(3000),
    SourceAddress = srcAddress,
    DestinationAddress = dstAddress,
};

using var traceroute = new TcpTraceRouteCapture(device, networkInterface, options);
    
traceroute.ProbeCompleted += (_, e) => 
{
    var p = e.Probe;
    Console.WriteLine($"ttl={p.Ttl} q={p.QueryNum} src={p.Address} delta={p.Delta}ms");
};

var result = traceroute.Run();

var destinationReached = result.Probes
    .TakeLast(opts.NumQueries)
    .Any(p => p.Address.Equals(opts.DestinationAddress));

if (!destinationReached)
{
    Console.WriteLine("Destination not reached");
}
```
