namespace TcpTraceRoute;

public record TcpTraceRouteResult
{
    public bool DestinationReached { get; set; }

    public int HopsNumber { get; init; }

    public IEnumerable<Probe> Probes { get; init; }

    public static TcpTraceRouteResult Failure => new() { DestinationReached = false };
}