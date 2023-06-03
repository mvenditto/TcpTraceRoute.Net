namespace TcpTraceRoute;

public class ProbeCompletedEventArgs : EventArgs
{
    public ProbeCompletedEventArgs(Probe probe)
    {
        Probe = probe;
    }

    public Probe Probe { get; init; }
}