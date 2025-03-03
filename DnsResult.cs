using System.Net;

public record DnsResult(IList<IPAddress> AnswerIps, IDictionary<string, IPAddress> NsServerIps);