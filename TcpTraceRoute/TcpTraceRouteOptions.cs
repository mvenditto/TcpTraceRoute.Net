using System.Net;

namespace TcpTraceRoute;

public record TcpTraceRouteOptions
{
    public ushort TcpDestinationPort { get; init; } = 80;

    public string? DestinationHostName { get; set; } = null;

    public required IPAddress? SourceAddress { get; set; }

    public required IPAddress DestinationAddress { get; set; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(3);

    public ushort SourcePort { get; set; } = 0;

    public string? SourceInterface { get; init; }

    public int TypeOfService { get; init; } = 0;

    public int MaxTtl { get; init; } = 10;

    public int FirstTtl { get; init; } = 1;

    public int NumQueries { get; init; } = 3;

    public int PacketLength { get; set; } = 0;

    public string? PacketPayload { get; init; } = null;

    public bool TrackPort { get; init; } = false;

    public bool UseDNat { get; init; } = false;

    public bool SetSynFlag { get; set; } = true;

    public bool SetAckFlag { get; init; } = false;

    public bool SetEcnFlag { get; init; } = false;

    public bool SetUrgFalg { get; init; } = false;

    public bool DontFrag { get; init; } = false;

    public bool ForcePort { get; init; } = false;
}
