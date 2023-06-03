# TcpTraceRoute

A TCP-based traceroute library and tool inspired by the original [`tcptraceroute`](https://github.com/mct/tcptraceroute).

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

<details>
<summary>traceroute-net github.com -q 1 -n --dot </summary>
  
<pre>
 Selected device Wi-Fi (Intel(R) Wi-Fi 6 AX201 160MHz), address 192.168.1.56, port 60563 for outgoing packets
 Tracing the path to github.com (140.82.121.3) on TCP port 80, 30 hops max
 1  192.168.1.1        1.873 ms  1.196 ms  1.230 ms
 [...TRUNCATED FOR BREVITY...]
 
 digraph {
  {
    host
    1[label="192.168.1.1" ]
    2[label="151.6.142.56" ]
    3[label="151.6.57.40" ]
    4[label="151.6.0.190" ]
    5[label="151.6.7.239" ]
    6[label="80.81.194.26" ]
    7[label="64.125.30.254" ]
    8[label="64.125.29.65" ]
    9[label="82.98.193.29" ]
    10[label="*" color=red]
    11[label="*" color=red]
    12[label="140.82.121.4" ]
  }
  host->1 [label="  2.228 ms"]
  host->2 [label="  8.137 ms" style=dotted]
  1->2 [label="  10.364 ms"]
  host->3 [label="  6.886 ms" style=dotted]
  2->3 [label="  17.250 ms"]
  host->4 [label="  26.925 ms" style=dotted]
  3->4 [label="  44.175 ms"]
  host->5 [label="  22.965 ms" style=dotted]
  4->5 [label="  67.140 ms"]
  host->6 [label="  23.855 ms" style=dotted]
  5->6 [label="  90.995 ms"]
  host->7 [label="  24.454 ms" style=dotted]
  6->7 [label="  115.449 ms"]
  host->8 [label="  62.802 ms" style=dotted]
  7->8 [label="  178.252 ms"]
  host->9 [label="  19.341 ms" style=dotted]
  8->9 [label="  197.593 ms"]
  host->10 [label="  -1.000 ms" style=dotted]
  9->10 [label="  197.593 ms"]
  host->11 [label="  -1.000 ms" style=dotted]
  10->11 [label="  197.593 ms"]
  host->12 [label="  19.376 ms" style=dotted]
  11->12 [label="  216.969 ms"]
}
See rendered at:
https://dreampuf.github.io/GraphvizOnline/#digraph%20%7B%0D%0A%20%20%7B%[...TRUNCATED...]
</pre>
  
[See render at dreampuf.github.io/GraphvizOnline](https://dreampuf.github.io/GraphvizOnline/#digraph%20%7B%0D%0A%20%20%7B%0D%0A%20%20%20%20host%0D%0A%20%20%20%201%5Blabel%3D%22192.168.1.1%22%20%5D%0D%0A%20%20%20%202%5Blabel%3D%22151.6.142.56%22%20%5D%0D%0A%20%20%20%203%5Blabel%3D%22151.6.57.40%22%20%5D%0D%0A%20%20%20%204%5Blabel%3D%22151.6.0.190%22%20%5D%0D%0A%20%20%20%205%5Blabel%3D%22151.6.7.239%22%20%5D%0D%0A%20%20%20%206%5Blabel%3D%2280.81.194.26%22%20%5D%0D%0A%20%20%20%207%5Blabel%3D%2264.125.30.254%22%20%5D%0D%0A%20%20%20%208%5Blabel%3D%2264.125.29.65%22%20%5D%0D%0A%20%20%20%209%5Blabel%3D%2282.98.193.29%22%20%5D%0D%0A%20%20%20%2010%5Blabel%3D%22%2A%22%20color%3Dred%5D%0D%0A%20%20%20%2011%5Blabel%3D%22%2A%22%20color%3Dred%5D%0D%0A%20%20%20%2012%5Blabel%3D%22140.82.121.4%22%20%5D%0D%0A%20%20%7D%0D%0A%20%20host-%3E1%20%5Blabel%3D%22%20%202.228%20ms%22%5D%0D%0A%20%20host-%3E2%20%5Blabel%3D%22%20%208.137%20ms%22%20style%3Ddotted%5D%0D%0A%20%201-%3E2%20%5Blabel%3D%22%20%2010.364%20ms%22%5D%0D%0A%20%20host-%3E3%20%5Blabel%3D%22%20%206.886%20ms%22%20style%3Ddotted%5D%0D%0A%20%202-%3E3%20%5Blabel%3D%22%20%2017.250%20ms%22%5D%0D%0A%20%20host-%3E4%20%5Blabel%3D%22%20%2026.925%20ms%22%20style%3Ddotted%5D%0D%0A%20%203-%3E4%20%5Blabel%3D%22%20%2044.175%20ms%22%5D%0D%0A%20%20host-%3E5%20%5Blabel%3D%22%20%2022.965%20ms%22%20style%3Ddotted%5D%0D%0A%20%204-%3E5%20%5Blabel%3D%22%20%2067.140%20ms%22%5D%0D%0A%20%20host-%3E6%20%5Blabel%3D%22%20%2023.855%20ms%22%20style%3Ddotted%5D%0D%0A%20%205-%3E6%20%5Blabel%3D%22%20%2090.995%20ms%22%5D%0D%0A%20%20host-%3E7%20%5Blabel%3D%22%20%2024.454%20ms%22%20style%3Ddotted%5D%0D%0A%20%206-%3E7%20%5Blabel%3D%22%20%20115.449%20ms%22%5D%0D%0A%20%20host-%3E8%20%5Blabel%3D%22%20%2062.802%20ms%22%20style%3Ddotted%5D%0D%0A%20%207-%3E8%20%5Blabel%3D%22%20%20178.252%20ms%22%5D%0D%0A%20%20host-%3E9%20%5Blabel%3D%22%20%2019.341%20ms%22%20style%3Ddotted%5D%0D%0A%20%208-%3E9%20%5Blabel%3D%22%20%20197.593%20ms%22%5D%0D%0A%20%20host-%3E10%20%5Blabel%3D%22%20%20-1.000%20ms%22%20style%3Ddotted%5D%0D%0A%20%209-%3E10%20%5Blabel%3D%22%20%20197.593%20ms%22%5D%0D%0A%20%20host-%3E11%20%5Blabel%3D%22%20%20-1.000%20ms%22%20style%3Ddotted%5D%0D%0A%20%2010-%3E11%20%5Blabel%3D%22%20%20197.593%20ms%22%5D%0D%0A%20%20host-%3E12%20%5Blabel%3D%22%20%2019.376%20ms%22%20style%3Ddotted%5D%0D%0A%20%2011-%3E12%20%5Blabel%3D%22%20%20216.969%20ms%22%5D%0D%0A%7D%0D%0A=)
  
</details>
    
## Addition features
## Route graph generation with `--dot`
`tcptraceroute-net github.com -q 1 --dot`
    
 See the *Cli - Samples* section for more details.

<picture>
<source
  srcset="/Docs/traceroute_dark.svg"
  media="(prefers-color-scheme: dark)"
/>
<source
  srcset="/Docs/traceroute.svg"
  media="(prefers-color-scheme: light), (prefers-color-scheme: no-preference)"
/>
<img src="/Docs/traceroute.svg" height="1000">
</picture>

    
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
    
## References
  - [tcptraceroute](https://github.com/mct/tcptraceroute)
  - [packetnet](https://github.com/dotpcap/packetnet)
  - [sharppcap](https://github.com/dotpcap/sharppcap)
  - [nmap - Host Discovery Techniques](https://nmap.org/book/host-discovery-techniques.html)
    
