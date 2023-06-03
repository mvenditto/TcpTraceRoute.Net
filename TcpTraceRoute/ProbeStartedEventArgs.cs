namespace TcpTraceRoute;

public class ProbeStartedEventArgs : EventArgs
{
    public ProbeStartedEventArgs(DateTime timestamp, ushort tcpSourcePort, int ttl, int queryNum)
    {
        TimeStamp = timestamp;
        TcpSourcePort = tcpSourcePort;
        TimeToLive = ttl;
        QueryNum = queryNum;
    }

    public DateTime TimeStamp { get; init; }

    public ushort TcpSourcePort { get; init; }

    public int TimeToLive { get; init; }    

    public int QueryNum { get; init; }
}