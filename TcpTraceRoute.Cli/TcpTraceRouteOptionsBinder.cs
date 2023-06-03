using System.CommandLine;
using System.CommandLine.Binding;
using System.Net;

namespace TcpTraceRoute.Cli;

internal class TcpTraceRouteOptionsBinder : BinderBase<TcpTraceRouteOptions>
{
    private readonly Option<int> _numQueries;
    private readonly Option<int> _firstTtl;
    private readonly Option<bool> _trackPort;
    private readonly Option<bool> _forcePort;
    private readonly Option<bool> _dnat;
    private readonly Option<string> _srcInterface;
    private readonly Option<int> _packetLenght;
    private readonly Option<int> _maxTtl;
    private readonly Option<int> _typeOfServie;
    private readonly Option<string> _srcAddress;
    private readonly Option<ushort> _srcPort;
    private readonly Option<int> _timeout;
    private readonly Argument<ushort> _dstPort;
    private readonly Argument<string> _dstAddress;
    private readonly Option<bool> _syn;
    private readonly Option<bool> _ack;
    private readonly Option<bool> _ecn;
    private readonly Option<bool> _urg;

    public TcpTraceRouteOptionsBinder(
        Option<int> numQueries,
        Option<int> firstTtl,
        Option<bool> trackPort,
        Option<bool> forcePort,
        Option<bool> dnat,
        Option<string> srcInterface,
        Option<int> packetLenght,
        Option<int> maxTtl,
        Option<int> typeOfService,
        Option<string> srcAddress,
        Option<ushort> srcPort,
        Option<int> timeout,
        Option<bool> syn,
        Option<bool> ack,
        Option<bool> ecn,
        Option<bool> urg,
        Argument<string> dstAddress,
        Argument<ushort> dstPort
    )
    {
        _numQueries = numQueries;
        _firstTtl = firstTtl;
        _trackPort = trackPort;
        _forcePort = forcePort;
        _dnat = dnat;
        _srcInterface = srcInterface;
        _packetLenght = packetLenght;
        _maxTtl = maxTtl;
        _typeOfServie = typeOfService;
        _srcAddress = srcAddress;
        _srcPort = srcPort;
        _timeout = timeout;
        _dstPort = dstPort;
        _dstAddress = dstAddress;
        _syn = syn;
        _ack = ack;
        _ecn = ecn;
        _urg = urg;
    }
    protected override TcpTraceRouteOptions GetBoundValue(BindingContext bindingContext)
    {
        T? OptValue<T>(Option<T> o)
        {
            return bindingContext.ParseResult.GetValueForOption<T>(o);
        }

        T? ArgValue<T>(Argument<T> a)
        {
            return bindingContext.ParseResult.GetValueForArgument<T>(a);
        }

        return new TcpTraceRouteOptions
        {
            MaxTtl = OptValue(_maxTtl),
            FirstTtl = OptValue(_firstTtl),
            PacketLength = OptValue(_packetLenght),
            TcpDestinationPort = ArgValue(_dstPort),
            Timeout = TimeSpan.FromMilliseconds(OptValue(_timeout)),
            TypeOfService = OptValue(_typeOfServie),
            NumQueries = OptValue(_numQueries),
            SourceAddress = string.IsNullOrEmpty(OptValue(_srcAddress)) ? null : IPAddress.Parse(OptValue(_srcAddress)),
            DestinationAddress = IPAddress.Parse(ArgValue(_dstAddress)),
            TrackPort = OptValue(_trackPort),
            UseDNat = OptValue(_dnat),
            ForcePort = OptValue(_forcePort),
            SetAckFlag = OptValue(_ack),
            SetSynFlag = OptValue(_syn),
            SetEcnFlag = OptValue(_ecn),
            SetUrgFalg = OptValue(_urg),
            SourcePort = OptValue(_srcPort)
        };
    }
}
