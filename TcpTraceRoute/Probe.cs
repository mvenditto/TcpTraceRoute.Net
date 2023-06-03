using PacketDotNet;
using SharpPcap;
using System.Net;

namespace TcpTraceRoute;

/// <summary>
/// describes the probe packet sent 
/// </summary>
public record Probe
{
    public ushort Id { get; init; }

    public int Ttl { get; init; }

    public int QueryNum { get; init; }

    public ushort SrcPort { get; init; }

    internal PosixTimeval TimeStamp { get; set; }

    public DateTime Date => TimeStamp.Date;

    public IPAddress DNatIp { get; internal set; } = IPAddress.None;

    public string State { get; internal set; } = string.Empty;

    public string String { get; internal set; } = string.Empty;

    public ushort DNatDstPort { get; internal set; }

    public IPAddress Address { get; internal set; } = IPAddress.None;

    public double Delta { get; internal set; }

    public bool Unreachable { get; internal set; }

    public IPv4Packet ProbeBeginPacket { get; internal set; }

    public Packet? EndPacket { get; internal set; }
}