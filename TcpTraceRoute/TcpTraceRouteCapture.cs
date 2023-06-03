using Microsoft.Extensions.Logging;
using PacketDotNet;
using PacketDotNet.Utils;
using PacketDotNet.Utils.Converters;
using Serilog.Context;
using SharpPcap;
using SharpPcap.LibPcap;
using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.NetworkInformation;
using System.Text;
using TcpTraceRoute.Helpers;

namespace TcpTraceRoute;

public class TcpTraceRouteCapture : IDisposable
{
    private readonly ILiveDevice _device;
    private readonly IPAddress _srcAddress;
    private readonly IPAddress _dstAddress;
    private readonly PhysicalAddress _dstMacAddress;
    private readonly PhysicalAddress _srcMacAddress;
    private readonly NetworkInterface _networkInterface;
    private readonly TcpTraceRouteOptions _opts;
    private readonly int _readTimeoutMilliseconds;
    private readonly ILogger? _logger;

    // the last executed probe for which we are trying to capture response packets
    private Probe? _currProbe;
    private bool _disposed;

    private const int IpV4HeaderMinimumLength = 0x14; // 20
    private const int TcpHeaderMinimumLength  = 0x14; // 20
    private const int IcmpHeaderMinimumLength = 0x04; //  4

    private const byte ICMP_UNREACH = 3;
    private const byte ICMP_TIMXCEED = 11;

    public event EventHandler<ProbeStartedEventArgs> ProbeStarted;
    public event EventHandler<ProbeCompletedEventArgs> ProbeCompleted;

    /// <summary>
    /// 
    /// </summary>
    /// <param name="device"></param>
    /// <param name="srcAddress"></param>
    /// <param name="dstAddress"></param>
    /// <param name="options"></param>
    /// <param name="packetReadTimeoutMilliseconds">
    /// The low level packet read all timeout in milliseconds.
    /// A small value (< 500) can cause missing query result in multi-query tests.
    /// </param>
    /// <param name="logger"></param>
    public TcpTraceRouteCapture(
        ILiveDevice device, 
        NetworkInterface networkInterface,
        TcpTraceRouteOptions options,
        PhysicalAddress? dstMacAddress = null,
        int packetReadTimeoutMilliseconds = 1000,
        ILogger? logger =null)
    {
        ArgumentNullException.ThrowIfNull(device);
        ArgumentNullException.ThrowIfNull(options.SourceAddress);
        ArgumentNullException.ThrowIfNull(options.DestinationAddress);
        ArgumentNullException.ThrowIfNull(networkInterface);
        ArgumentNullException.ThrowIfNull(options);

        Initialize(options);

        _logger = logger;
        _device = device;
        _opts = options;
        _srcMacAddress = _device.MacAddress;
        _networkInterface = networkInterface;
        _srcAddress = options.SourceAddress;
        _dstAddress = options.DestinationAddress;
        _readTimeoutMilliseconds = packetReadTimeoutMilliseconds;

        Thread.CurrentThread.CurrentCulture = CultureInfo.InvariantCulture;

        if (dstMacAddress == null)
        {
            try
            {
                _device.Open();
                var gatewayAddresses = _networkInterface.GetIPProperties().GatewayAddresses;

                foreach (var gatewayIp in gatewayAddresses)
                {
                    _dstMacAddress = new ARP((LibPcapLiveDevice)device).Resolve(gatewayIp.Address);
                    if (_dstMacAddress != null)
                    {
                        _logger?.LogDebug("Destination physical address resolved to: {DstMac}", _dstMacAddress);
                        break;
                    }
                }
            }
            catch
            {
                throw;
            }
            finally
            {
                _device.Close();
            }

            if (_dstMacAddress == null)
            {
                throw new Exception("Unable to resolve physical address.");
            }
        }
    }

    private void Initialize(TcpTraceRouteOptions o)
    {
        if (!o.ForcePort)
            o.SourcePort = NetworkHelpers.AllocatePort(o.SourcePort);
        
        if (o.FirstTtl <= 0 || o.MaxTtl <= 0)
            throw new ArgumentException("TTL must be greater than 0");

        if (o.FirstTtl >= 256 || o.MaxTtl >= 256)
            throw new ArgumentException("TTL must be less than 256");

        if (o.FirstTtl > o.MaxTtl)
            throw new ArgumentException($"Minimum TTL ({o.FirstTtl}) must be less than maximum TTL ({o.MaxTtl})");

        if (o.NumQueries <= 0)
            throw new ArgumentException("Number of queries must be at least 1");

        if (o.Timeout.TotalMilliseconds <= 0)
            throw new ArgumentException("Timeout must be at least 1");

        if (o.PacketLength < IpV4HeaderMinimumLength + TcpHeaderMinimumLength)
        {
            if (o.PacketLength != 0)
            {
                _logger?.LogWarning("Increasing packet length to {NewPacketLen} bytes", IpV4HeaderMinimumLength + TcpHeaderMinimumLength);
            }
            o.PacketLength = 0;
        }
        else
        {
            o.PacketLength -= IpV4HeaderMinimumLength + TcpHeaderMinimumLength;
        }

        if (!o.SetAckFlag && !o.SetSynFlag)
        {
            _logger?.LogDebug("Setting -S, in absence of either -S (syn) or -A (ack)");
            o.SetSynFlag = true;
        }
    }

    private void SetCaptureFilter()
    {
        const string filterTemplate = "(tcp and src host {0} and src port {1} and dst host {2}) or ((icmp[0] == 11 or icmp[0] == 3) and dst host {3})";
        
        var filter = string.Format(
            filterTemplate, 
            _dstAddress, 
            _opts.TcpDestinationPort, 
            _srcAddress,
            _srcAddress);

        _logger?.LogDebug("Capture filter: {Filter}", filter);

        _device.Filter = filter;
    }

    private bool HandleIcmpPacket(IPv4Packet ipPacket, IcmpV4Packet icmpPacket)
    {
        var len = icmpPacket.HeaderSegment.BytesLength;

        if (len < IpV4HeaderMinimumLength + IcmpHeaderMinimumLength + 4)
        {
            _logger?.LogDebug("Ignoring partial ICMP packet");
            return false;
        }

        if (len < IpV4HeaderMinimumLength + IcmpHeaderMinimumLength + 4 + IpV4HeaderMinimumLength + 8)
        {
            // aka tcp src and dst port wouldn't be there
            _logger?.LogDebug("Ignoring ICMP with incomplete payload");
            return false;
        }

        // Icmp Data contains the IPv4 packet header + 8 bytes payload of the packet
        // that generated the icmp error. This is called the quoted packet.
        var quotedIpPacket = new IPv4Packet(new ByteArraySegment(icmpPacket.Data));

        if (quotedIpPacket.Version != IPVersion.IPv4)
        {
            _logger?.LogDebug("Ignoring ICMP which quotes a non-IPv4 packet");
            return false;
        }

        if (quotedIpPacket.HeaderLength > 5) // 5 32bit DWORDS (20 byte)
        {
            _logger?.LogDebug("Ignoring ICMP which quotes an IP packet with IP options");
            return false;
        }

        if (!quotedIpPacket.SourceAddress.Equals(_srcAddress))
        {
            _logger?.LogDebug("Ignoring ICMP with incorrect quoted source ({PacketSrcAddress}, not {ExpectedSrcAddress})", quotedIpPacket.SourceAddress, _srcAddress);
            return false;
        }

        if (quotedIpPacket.Protocol != ProtocolType.Tcp)
        {
            _logger?.LogDebug("Ignoring ICMP which doesn't quote a TCP header");
            return false;
        }

        if (!_opts.TrackPort && quotedIpPacket.Id != _currProbe.Id)
        {
            _logger?.LogDebug("Ignoring ICMP which doesn't contain the IPID we sent");
            return false;
        }

        // The IP header, plus eight bytes of it's payload that generated
        // the ICMP packet is quoted here, prepended with four bytes of padding.
        var quotedIpHeader = quotedIpPacket.HeaderSegment;

        // The entire TCP header isn't here
        // but the source port destination port, and sequence number fields are.
        var quotedTcpSourcePort = EndianBitConverter.Big.ToUInt16(
            quotedIpHeader.Bytes, 
            quotedIpHeader.Length + TcpFields.SourcePortPosition);

        var quotedTcpDestinationPort = EndianBitConverter.Big.ToUInt16(
            quotedIpHeader.Bytes,
            quotedIpHeader.Length + TcpFields.DestinationPortPosition);

        _logger?.LogDebug("HANDLE QUOTED IP packet: ipid={IpId} SrcAddress={SrcAddress}, DstAddress={DstAddress} Proto={Proto} SrcPort={SrcPort} DstPort={DstPort}",
                quotedIpPacket.Id,
                quotedIpPacket.SourceAddress,
                quotedIpPacket.DestinationAddress,
                quotedIpPacket.Protocol,
                quotedTcpSourcePort,
                quotedTcpDestinationPort);
        
        if (quotedTcpSourcePort != _currProbe.SrcPort)
        {
            _logger?.LogDebug("Ignoring ICMP which doesn't quote the correct TCP source port");
            return false;
        }

        if (quotedTcpDestinationPort != _opts.TcpDestinationPort)
        {
            // Very strict checking, no DNAT detection
            if (_opts.UseDNat == false)
            {
                _logger?.LogDebug("Ignoring ICMP which doesn't quote the correct TCP destination ");
                return false;
            }

            // DNAT detection
            _currProbe.DNatDstPort = quotedTcpDestinationPort;
        }

        // type only
        var icmpType = icmpPacket.HeaderSegment[IcmpV4Fields.TypeCodePosition];

        if (icmpType == ICMP_UNREACH)
        {
            var unreachReason = icmpPacket.TypeCode switch
            {
                IcmpV4TypeCode.UnreachableNet => "!N",
                IcmpV4TypeCode.UnreachableHost => "!H",
                IcmpV4TypeCode.UnreachableProtocol => "!P",
                IcmpV4TypeCode.UnreachablePort => "!p",
                IcmpV4TypeCode.UnreachableFragmentationNeeded => "!F",
                IcmpV4TypeCode.UnreachableSourceRouteFailed => "!S",
                IcmpV4TypeCode.UnreachableDestinationNetworkUnknown | IcmpV4TypeCode.UnreachableDestinationHostUnknown => "!U",
                IcmpV4TypeCode.UnreachableSourceHostIsolated => "!I",
                IcmpV4TypeCode.UnreachableNetworkProhibited => "!A",
                IcmpV4TypeCode.UnreachableHostProhibited => "!C",
                IcmpV4TypeCode.UnreachableNetworkUnreachableForServiceType |
                IcmpV4TypeCode.UnreachableHostUnreachableForServiceType |
                IcmpV4TypeCode.UnreachableCommunicationProhibited |
                IcmpV4TypeCode.UnreachableHostPrecedenceViolation |
                IcmpV4TypeCode.UnreachablePrecedenceCutoffInEffect => $"!<{(int)icmpPacket.TypeCode}>",
                _ => string.Empty,
            };

            _currProbe.Address = ipPacket.SourceAddress;
            _currProbe.String = unreachReason;
            _currProbe.EndPacket = icmpPacket;
            return true;
        }

        if (icmpType == ICMP_TIMXCEED)
        {
            // If all of the fields of the IP, ICMP, quoted IP, and
            // quoted IP payload are consistent with the probe packet we
            // sent, yet the quoted destination address is different than
            // the address we're trying to reach, it's likely the
            // preceding hop was performing DNAT.

            if (!quotedIpPacket.DestinationAddress.Equals(_dstAddress))
            {
                // Very strict checking, no DNAT detection
                if (_opts.UseDNat == false)
                {
                    _logger?.LogDebug("Ignoring ICMP with incorrect quoted destination ({PacketDstAddress}, not {ExpectedDstAddress})", quotedIpPacket.DestinationAddress, _dstAddress);
                    return false;
                }
                else
                {
                    _currProbe.DNatIp = quotedIpPacket.DestinationAddress;
                }
            }

            _currProbe.Address = ipPacket.SourceAddress;
            _currProbe.EndPacket = icmpPacket;
            return true;
        }

        if (icmpType != ICMP_UNREACH && icmpType != ICMP_TIMXCEED)
        {
            // IcmpV4TypeCode != ICMP_TIMXCEED && IcmpV4TypeCode =! ICMP_UNREACH
            _currProbe.Address = ipPacket.SourceAddress;
            _currProbe.String = "-- Unexpected ICMP";
            _currProbe.EndPacket = icmpPacket;
            return true;
        }

        _logger?.LogCritical("Something bad happened");
        return false;
    }

    private bool HandleTcpPacket(IPv4Packet ipPacket, TcpPacket tcpPacket)
    {
        if (!ipPacket.SourceAddress.Equals(_dstAddress))
        {
            _logger?.LogDebug("Ignoring TCP from source ({SrcAddress}) different than target ({TargetAddress})", ipPacket.SourceAddress, _dstAddress);
            return false;
        }

        if (tcpPacket.HeaderSegment.BytesLength < TcpHeaderMinimumLength + IpV4HeaderMinimumLength)
        {
            _logger?.LogDebug("Ignoring partial TCP packet");
            return false;
        }

        if (tcpPacket.SourcePort != _opts.TcpDestinationPort || tcpPacket.DestinationPort != _currProbe?.SrcPort)
        {
            _logger?.LogDebug("Ignoring TCP which doesn't match the correct port numbers");
            return false;
        }

        var state = "no flags";

        if ((tcpPacket.Flags & TcpFields.ResetMask) != 0)
        {
            // RST
            state = "reset";
        }
        else if (tcpPacket.Synchronize
            && tcpPacket.Acknowledgment 
            && tcpPacket.ExplicitCongestionNotificationEcho 
            )
        {
            // SYN & ACK & ECN
            state = "open, ecn";
        }
        else if (tcpPacket.Synchronize 
            && tcpPacket.Acknowledgment)
        {
            // SYN & ACK
            state = "open";
        }
        else
        {
            if (tcpPacket.Reset) state += " RST";
            if (tcpPacket.Synchronize) state += " SYN";
            if (tcpPacket.Acknowledgment) state += " ACK";
            if (tcpPacket.Push) state += " PSH";
            if (tcpPacket.Finished) state += " FIN";
            if (tcpPacket.Urgent) state += " URG";
            if (tcpPacket.CongestionWindowReduced) state += " CWR";
            if (tcpPacket.ExplicitCongestionNotificationEcho) state += " ECN";
        }

        _currProbe.State = state;
        _currProbe.Address = ipPacket.SourceAddress;
        _currProbe.EndPacket = tcpPacket;
        return true;
    }

    public bool HandlePacket(PacketCapture e)
    {
        if (_currProbe == null) return false;

        /*
        checked
        {
            
            var delta = (double)(e.Header.Timeval.Seconds - _currProbe.TimeStamp.Seconds) * 1000 +
                (double)(e.Header.Timeval.MicroSeconds - _currProbe.TimeStamp.MicroSeconds) / 1000;
        }*/

        var delta = e.Header.Timeval.Value - _currProbe.TimeStamp.Value;
        _currProbe.Delta = (double) delta * 1000.0;    
        
        _logger?.LogDebug("Packet received, start processing: delta = {Delta} ms", delta);

        try
        {
            var rawPacket = e.GetPacket();
            var packet = Packet.ParsePacket(rawPacket.LinkLayerType, rawPacket.Data);
            
            if (packet == null)
            {
                _logger?.LogDebug("Cannot parse packet of with link type: {DataLinkType}", rawPacket.LinkLayerType);
                return false;
            }

            var ipPacket = packet.Extract<IPv4Packet>();

            if (ipPacket == null)
            {
                _logger?.LogDebug("Ignoring non-IPv4 packet.");
                return false;
            }

            _logger?.LogDebug("HANDLE IP packet: SrcAddress={SrcAddress}, DstAddress={DstAddress} Proto={Proto}", 
                ipPacket.SourceAddress,
                ipPacket.DestinationAddress,
                ipPacket.Protocol);

            if (!ipPacket.DestinationAddress.Equals(_srcAddress))
            {
                _logger?.LogDebug("Ignoring IP packet not addressed to us ({PacketSrcAddress}, not {SrcAddress})", ipPacket.SourceAddress, _srcAddress);
                return false;
            }

            if (ipPacket.Protocol == ProtocolType.Icmp)
            {
                var icmpPacket = packet.Extract<IcmpV4Packet>();

                // Console.WriteLine(icmpPacket.ToString(StringOutputType.Colored));

                if (icmpPacket == null)
                {
                    _logger?.LogDebug("Cannot extract ICMP packet");
                    return false;
                }

                _logger?.LogDebug("HANDLE ICMP packet: TypeCode={TypCode}", icmpPacket.TypeCode);
                
                return HandleIcmpPacket(ipPacket, icmpPacket);
            }
            else if (ipPacket.Protocol == ProtocolType.Tcp)
            {
                var tcpPacket = packet.Extract<TcpPacket>();

                // Console.WriteLine(tcpPacket.ToString(StringOutputType.Colored));

                if (tcpPacket == null)
                {
                    _logger?.LogDebug("Cannot extract TCP packet");
                    return false;
                }

                _logger?.LogDebug("HANDLE TCP packet: SrcPort={SrcPort} DstPort={DstPort} Flags=0x{Flags:X8}", 
                    tcpPacket.SourcePort,
                    tcpPacket.DestinationPort,
                    tcpPacket.Flags);

                return HandleTcpPacket(ipPacket, tcpPacket);
            }
            else
            {
                _logger?.LogDebug("Ignoring non-ICMP and non-TCP packet");
            }
        }
        catch (Exception ex)
        {
            _logger?.LogDebug(ex, "Ignore packet, Error while processing.");
        }

        return false;
    }

    private EthernetPacket CreateProbeWirePacket(Probe probe)
    {
        var ipPacket = new IPv4Packet(_srcAddress, _dstAddress)
        {
            TypeOfService = _opts.TypeOfService
        };

        if (_opts.DontFrag)
        {
            throw new NotImplementedException();
        }

        ipPacket.TimeToLive = probe.Ttl;
        ipPacket.Protocol = ProtocolType.Tcp;

        var tcpPacket = new TcpPacket(probe.SrcPort, _opts.TcpDestinationPort)
        {
            Synchronize = _opts.SetSynFlag,
            Acknowledgment = _opts.SetAckFlag,
            ExplicitCongestionNotificationEcho = _opts.SetEcnFlag,
            CongestionWindowReduced = _opts.SetEcnFlag,
            Urgent = _opts.SetUrgFalg
        };

        if (_opts.PacketLength > 0 && _opts.PacketPayload == null)
        {
            tcpPacket.PayloadData = new byte[_opts.PacketLength];
            for (var i = 0; i < _opts.PacketLength; i++)
            {
                tcpPacket.PayloadData[i] = (byte)(i % ('~' - '!') + '!');
            }
            // Console.WriteLine(Encoding.ASCII.GetString(tcpPacket.PayloadData));
        }
        else if (_opts.PacketPayload != null)
        {
            tcpPacket.PayloadData = Encoding.ASCII.GetBytes(_opts.PacketPayload);
        }

        ipPacket.Id = probe.Id;
        ipPacket.PayloadPacket = tcpPacket;

        tcpPacket.UpdateTcpChecksum();
        ipPacket.UpdateIPChecksum();

        var ethernetPacket = new EthernetPacket(
            _device.MacAddress,
            _dstMacAddress,
            EthernetType.IPv4)
        {
            PayloadPacket = ipPacket
        };

        return ethernetPacket;
    }

    private void SendProbe(Probe probe)
    {
        var ethernetPacket = CreateProbeWirePacket(probe);

        probe.ProbeBeginPacket = (IPv4Packet) ethernetPacket.PayloadPacket;

        probe.TimeStamp = new PosixTimeval();

        _device.SendPacket(ethernetPacket);
    }

    public TcpTraceRouteResult Run(CancellationToken cancellationToken = default)
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(TcpTraceRouteCapture));
        }

        try
        {
            return RunInternal(cancellationToken);
        }
        catch (Exception ex)
        {
            _logger?.LogError(ex, "Tracerotue failure");
        }
        finally
        {
            _device.StopCapture();
            _device.Close();
        }

        return TcpTraceRouteResult.Failure;
    }

    private TcpTraceRouteResult RunInternal(CancellationToken cancellation = default)
    {
        _device.Open(DeviceModes.Promiscuous, _readTimeoutMilliseconds);
        _device.StopCaptureTimeout = _opts.Timeout;

        SetCaptureFilter();

        var handled = false;
        var timeout = false;
        var destinationReached = false;

        var sw = new Stopwatch();

        var probes = new List<Probe>();

        for (var ttl = 1; ttl <= _opts.MaxTtl && !destinationReached; ttl++)
        {
            if (cancellation.IsCancellationRequested) break;

            for (var q = 1; q <= _opts.NumQueries; q++)
            {
                if (cancellation.IsCancellationRequested) break;

                _currProbe = new Probe
                {
                    QueryNum = q,
                    Ttl = ttl,
                    Address = IPAddress.Any,
                    DNatIp = IPAddress.Any,
                    SrcPort = _opts.SourcePort,
                    Id = (ushort) Random.Shared.Next()
                };

                using var _ = LogContext.PushProperty("ProbeId", _currProbe.Id);

                _logger?.LogDebug("BEGIN Probe q={Query}/{MaxQuery} srcPort={SrcPort} ttl={Ttl}", q, _opts.NumQueries, _currProbe.SrcPort, ttl);
                
                _logger?.LogDebug("SEND Packet: ttl={Ttl} SrcAddress={SrcAddress}, DstAddress={DstAddress} Proto={Proto} SrcPort={SrcPort} DstPort={DstPort}",
                    ttl,
                    _srcAddress,
                    _dstAddress,
                    "Tcp",
                    _currProbe.SrcPort,
                    _opts.TcpDestinationPort);

                SendProbe(_currProbe);

                ProbeStarted?.Invoke(this, new(_currProbe.TimeStamp.Date, _currProbe.SrcPort, ttl, q));
                
                sw.Restart();

                handled = false;
                timeout = false;

                while(!cancellation.IsCancellationRequested)
                {
                    if (sw.Elapsed >= _opts.Timeout)
                    {
                        timeout = true;
                        break;
                    }

                    var res = _device.GetNextPacket(out var e);

                    if (res != GetPacketStatus.PacketRead) continue;

                    handled = HandlePacket(e);

                    if (handled)
                    {
                        destinationReached = _currProbe.Address.Equals(_dstAddress);
                        break;
                    }
                }

                sw.Stop();

                _logger?.LogDebug("DONE Probe q={Query}/{MaxQuery} handled={Handled} wait={WaitedMs} timeout={Timeout} reached={Reached} delta={Delta} status={Status} srcAddr={SrcAddress} srcPort={SrcPort}",
                    q,
                    _opts.NumQueries,
                    handled,
                    sw.Elapsed.TotalMilliseconds.ToString("0.###", CultureInfo.InvariantCulture) + " ms",
                    timeout,
                    destinationReached,
                    _currProbe.Delta.ToString("0.###", CultureInfo.InvariantCulture) + " ms",
                    _currProbe.State + _currProbe.String,
                    _currProbe.Address,
                    _currProbe.SrcPort);

                if (cancellation.IsCancellationRequested) break;

                ProbeCompleted?.Invoke(this, new(_currProbe));

                probes.Add(_currProbe);
            }
        }

        return new TcpTraceRouteResult
        {
            DestinationReached = destinationReached,
            HopsNumber = probes.Count / _opts.NumQueries,
            Probes = probes
        };
    }

    public void Dispose()
    {
        _disposed = true;
        _device.StopCapture();
        _device.Close();
        _device.Dispose();
        GC.SuppressFinalize(this);
    }
}
