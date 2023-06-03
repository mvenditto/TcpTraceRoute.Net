using Microsoft.Extensions.Logging.Abstractions;
using Serilog.Extensions.Logging;
using Serilog;
using System.CommandLine;
using TcpTraceRoute;
using TcpTraceRoute.Cli;
using TcpTraceRoute.Helpers;
using System.Globalization;
using System.Net;
using System.CommandLine.Parsing;
using Microsoft.Extensions.Logging;
using DnsClient;
using System.Text;
using System.Reflection.Emit;

var numQueryOption = new Option<int>(new[] { "-q", "--num-queries" }, () => 3);
var firstTtlOption = new Option<int>(new[] { "-f", "--first-ttl"},  () => 1);
var interfaceOption = new Option<string>(new[] { "-i", "--interface" });
var packetLenOption = new Option<int>(new[] { "-l", "--packet-len" }, () => 0);
var maxTtlOption = new Option<int>(new[] { "-m", "--max-ttl" }, () => 30);
var typeOfServiceOption = new Option<int>(new[] { "-t", "--tos" }, () => 0);
var sourceAddressOption = new Option<string>(new[] { "-s", "--src-address" });
var sourcePortOption = new Option<ushort>(new[] { "-p", "--src-port" }, () => 0);
var timeoutOption = new Option<int>(new[] { "-w", "--wait-time"}, description: "packet read timeout (ms)", getDefaultValue: () => 3000);
var destHostArgument = new Argument<string>("dst-host");
var destPortArgument = new Argument<ushort>("dst-port", () => 80);
var dnatOption = new Option<bool>(new[] { "--dnat" }, () => false);
var trackPortOption = new Option<bool>(new[] { "--track-port" }, () => false);
var forcePortOption = new Option<bool>(new[] { "-P", "--force-port" }, () => false);
var numericOption = new Option<bool>("-n", () => true, "dot not resolve probe hostname");
var tcpSynOption = new Option<bool>("-S", () => true, "set SYN tcp flag");
var tcpAckOption = new Option<bool>("-A", () => false, "set ACK tcp flag");
var tcpEcnOption = new Option<bool>("-E", () => false, "set ECN tcp flag");
var tcpUrgOption = new Option<bool>("-U", () => false, "set URG tcp flag");
var debugOption = new Option<bool>("-d", () => false, "debug mode");
var dotOption = new Option<bool>("--dot", () => false, "produce dot graph");

var rootCommand = new RootCommand()
{
    debugOption,
    numericOption,
    dotOption,
    numQueryOption,
    firstTtlOption,
    trackPortOption,
    forcePortOption,
    dnatOption,
    interfaceOption,
    packetLenOption,
    maxTtlOption,
    typeOfServiceOption,
    sourceAddressOption,
    sourcePortOption,
    timeoutOption,
    tcpSynOption,
    tcpAckOption,
    tcpEcnOption,
    tcpUrgOption,
    destHostArgument,
    destPortArgument
};

static async Task DoTraceRoute(TcpTraceRouteOptions opts, bool debug, bool numeric, bool generateDotGraph)
{
    var logger = (Microsoft.Extensions.Logging.ILogger) NullLogger.Instance;

    if (debug)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss.fff} {Level:u3}] [{ProbeId:D5}] {Message}{NewLine}{Exception}")
            .MinimumLevel.Debug()
            .Enrich.FromLogContext()
            .CreateLogger();

        logger = new SerilogLoggerFactory(Log.Logger).CreateLogger("TcpTraceRoute");
    }

    var stdout = debug ? TextWriter.Null : Console.Out;

    if (opts.TrackPort)
    {
        throw new NotImplementedException("trackport");
    }

    if (opts.SourceAddress == null)
    {
        opts.SourceAddress = await NetworkHelpers.FindSourceAddress(opts.DestinationAddress);

        if (opts.SourceAddress == null)
        {
            throw new Exception("Cannot find the source address from the specified destination.");
        }
    }

    var (device, networkInterface) = NetworkHelpers.FindDevice(opts.SourceAddress);

    if (device == null || networkInterface == null)
    {
        throw new Exception("Unable to find a suitable device");
    }

    using var traceroute = new TcpTraceRouteCapture(
        device,
        networkInterface,
        opts,
        packetReadTimeoutMilliseconds: 200,
        logger: logger);


    stdout.Write($"Selected device {device.FriendlyName()} ({device.Description}), address {opts.SourceAddress}");

    if (!opts.TrackPort)
    {
        stdout.Write($", port {opts.SourcePort}");
    }

    stdout.WriteLine(" for outgoing packets");

    int lastTtl = 1;

    stdout.WriteLine();

    var dns = new LookupClient(new LookupClientOptions 
    { 
        Timeout = TimeSpan.FromMilliseconds(1000),
    });

    traceroute.ProbeCompleted += (_, e) =>
    {
        var probe = e.Probe;

        // different hop
        if (probe.Ttl != lastTtl)
        {
            lastTtl = probe.Ttl;
            stdout.WriteLine();
        }

        // first query, write the host
        if (probe.QueryNum == 1)
        {
            string hopHost = probe.Address == IPAddress.Any ? "*" : probe.Address.ToString();

            if (!numeric)
            {
                try
                {
                    var hostEntry = dns.GetHostEntry(probe.Address);
                    hopHost = hostEntry?.HostName ?? hopHost;
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "DNS query failed for {ProbeAddress}", probe.Address);
                }
            }

            var state = string.IsNullOrEmpty(probe.State) ? "" : $"[{probe.State}]";
            stdout.Write($"{probe.Ttl,2}  {hopHost,-15}  {probe.String ?? ""}{state}  ");
        }

        // write the query latency
        if (probe.Delta > 0 && probe.Address != IPAddress.Any)
        {
            stdout.Write(probe.Delta.ToString("0.000", CultureInfo.InvariantCulture) + " ms  ");
        }
        else
        {
            stdout.Write("*  ");
        }
    };

    var dst = opts.DestinationHostName;

    if (opts.DestinationHostName != opts.DestinationAddress.ToString())
    {
        dst += $" ({opts.DestinationAddress})";
    }

    stdout.Write($"Tracing the path to {dst} on TCP port {opts.TcpDestinationPort}, {opts.MaxTtl} hops max");

    if (opts.PacketLength > 0)
    {
        stdout.Write($", {opts.PacketLength + 20 + 20} byte packets");
    }

    stdout.WriteLine();

    var result = traceroute.Run();

    var destinationReached = result.Probes
        .TakeLast(opts.NumQueries)
        .Any(p => p.Address.Equals(opts.DestinationAddress));

    if (!destinationReached)
    {
        stdout.WriteLine("Destination not reached");
    }

    if (generateDotGraph)
    {
        var sb = new StringBuilder();
        sb.AppendLine("digraph {");
        sb.AppendLine("  {");
        sb.AppendLine("    host");

        var hops = result.Probes.Chunk(opts.NumQueries).ToArray();

        foreach (var hop in hops)
        {
            var probe = hop.FirstOrDefault(x => x.Address != IPAddress.Any) ?? hop[0];

            string hopHost = probe.Address == IPAddress.Any ? "*" : probe.Address.ToString();

            if (!numeric)
            {
                try
                {
                    var hostEntry = dns.GetHostEntry(probe.Address);
                    hopHost = hostEntry?.HostName ?? hopHost;
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "DNS query failed for {ProbeAddress}", probe.Address);
                }
            }

            var attrs = string.Empty;

            if (hopHost == "*")
            {
                attrs += "color=red";
            }

            sb.AppendLine($"    {hop[0].Ttl}[label=\"{hopHost}\" {attrs}]");
        }
        sb.AppendLine("  }");

        var totDelta = hops[0].Where(x => x.Address != IPAddress.Any && x.Delta > 0).Average(x => x.Delta);
        var label = totDelta.ToString("0.000", CultureInfo.InvariantCulture) + " ms";
        sb.AppendLine($"  host->1 [label=\"  {label}\"]");

        for(var i = 1; i < result.HopsNumber; i++)
        {
            if (i + 1 <= result.HopsNumber)
            {
                var hop = hops[i];

                label = string.Empty;
                var attrs = string.Empty;
                var avgDelta = -1.0;

                if (hop.Any(x => x.Address != IPAddress.Any))
                {
                    avgDelta = hop.Where(x => x.Address != IPAddress.Any && x.Delta > 0).Average(x => x.Delta);
                    totDelta += avgDelta;
                }
                else
                {
                    attrs = "color=red";
                }
                label = totDelta.ToString("0.000", CultureInfo.InvariantCulture) + " ms";
                var hostDelta = avgDelta.ToString("0.000", CultureInfo.InvariantCulture) + " ms";

                sb.AppendLine($"  host->{i + 1} [label=\"  {hostDelta}\" style=dotted]");
                sb.AppendLine($"  {i}->{i + 1} [label=\"  {label}\"]");
            }
        }

        sb.AppendLine("}");

        var dot = sb.ToString();
        var graphVizUrl = $"https://dreampuf.github.io/GraphvizOnline/#{Uri.EscapeDataString(dot)}";

        Console.WriteLine("Dot graph: \n");
        Console.WriteLine(dot);
        Console.WriteLine("Rendered at: \n");
        Console.WriteLine(graphVizUrl);
    }


    stdout.WriteLine();
}

rootCommand.SetHandler(
    async (debug, numeric, generateDotGraph, traceRouteOptions) => 
    {
       await DoTraceRoute(traceRouteOptions, debug, numeric, generateDotGraph);
    },
    debugOption,
    numericOption,
    dotOption,
    new TcpTraceRouteOptionsBinder(
        numQueryOption,
        firstTtlOption,
        trackPortOption,
        forcePortOption,
        dnatOption,
        interfaceOption,
        packetLenOption,
        maxTtlOption,
        typeOfServiceOption,
        sourceAddressOption,
        sourcePortOption,
        timeoutOption,
        tcpSynOption,
        tcpAckOption,
        tcpEcnOption,
        tcpUrgOption,
        destHostArgument,
        destPortArgument
    )
);

await rootCommand.InvokeAsync(args);
