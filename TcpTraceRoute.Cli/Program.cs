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
var tcpSynOption = new Option<bool>("-S", () => true, "set SYN tcp flag");
var tcpAckOption = new Option<bool>("-A", () => false, "set ACK tcp flag");
var tcpEcnOption = new Option<bool>("-E", () => false, "set ECN tcp flag");
var tcpUrgOption = new Option<bool>("-U", () => false, "set URG tcp flag");
var debugOption = new Option<bool>("-d", () => false, "debug mode");

var rootCommand = new RootCommand()
{
    debugOption,
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

static async Task DoTraceRoute(TcpTraceRouteOptions opts, bool debug)
{
    var logger = (Microsoft.Extensions.Logging.ILogger) NullLogger.Instance;

    if (debug)
    {
        Log.Logger = new LoggerConfiguration()
            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss.fff} {Level:u3}] [{ProbeId:D5}] {Message}{NewLine}{Exception}")
            .MinimumLevel.Information()
            .Enrich.FromLogContext()
            .CreateLogger();

        logger = new SerilogLoggerFactory(Log.Logger).CreateLogger("TcpTraceRoute");
    }

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


    Console.Write($"Selected device {device.FriendlyName()} ({device.Description}), address {opts.SourceAddress}");

    if (!opts.TrackPort)
    {
        Console.Write($", port {opts.SourcePort}");
    }

    Console.WriteLine(" for outgoing packets");

    int lastTtl = 1;

    Console.WriteLine();

    traceroute.ProbeCompleted += (_, e) =>
    {
        var probe = e.Probe;

        // different hop
        if (probe.Ttl != lastTtl)
        {
            lastTtl = probe.Ttl;
            Console.WriteLine();
        }

        // first query, write the host
        if (probe.QueryNum == 1)
        {
            var hopAddr = probe.Address == IPAddress.Any ? "*" : probe.Address.ToString();
            var state = string.IsNullOrEmpty(probe.State) ? "" : $"[{probe.State}]";
            Console.Write($"{probe.Ttl,2}  {hopAddr,-15}  {probe.String ?? ""}{state}  ");
        }

        // write the query latency
        if (probe.Delta > 0 && probe.Address != IPAddress.Any)
        {
            Console.Write(probe.Delta.ToString("0.000", CultureInfo.InvariantCulture) + " ms  ");
        }
        else
        {
            Console.Write("*  ");
        }
    };

    Console.Write($"Tracing the path to {opts.DestinationAddress} on TCP port {opts.TcpDestinationPort}, {opts.MaxTtl} hops max");

    if (opts.PacketLength > 0)
    {
        Console.Write($", {opts.PacketLength + 20 + 20} byte packets");
    }

    Console.WriteLine();

    var result = traceroute.Run();

    var destinationReached = result.Probes
        .TakeLast(opts.NumQueries)
        .Any(p => p.Address.Equals(opts.DestinationAddress));

    if (!destinationReached)
    {
        Console.WriteLine("Destination not reached");
    }

    Console.WriteLine();
}

rootCommand.SetHandler(
    async (debug, traceRouteOptions) => 
    {
       await DoTraceRoute(traceRouteOptions, debug);
    },
    debugOption,
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
