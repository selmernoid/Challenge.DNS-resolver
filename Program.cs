using System;
using System.Net;
using System.Net.Sockets;

IPAddress rootNameserver = IPAddress.Parse("198.41.0.4");
var header = new DnsHeader
{
    Id = 12345,
    Flags = 0x0000, // Standard query
    QdCount = 1,
    AnsCount = 0,
    NSCount = 0,
    AnmCount = 0,
    RClass = 1, // IN class
    Rdtype = 1, // A record
};

string domain = "dns.google.com";

var encodedDnsPacket = DnsEncoder.EncodeHeader(header, domain);

Console.WriteLine("Encoded DNS Packet:");
foreach (var b in encodedDnsPacket)
{
    Console.Write($"{b:X2} ");
}

var ip = rootNameserver;
while (true)
{
    var result = await GetDnsResult(ip, encodedDnsPacket);
    if (result.AnswerIps.Any())
    {
        Console.WriteLine($"Finally reached domain IP: {string.Join(", ", result.AnswerIps)}");
        return;
    }

    if (!result.NsServerIps.Any())
    {
        throw new InvalidDataException("There is no Authorities.");
    }

    ip = result.NsServerIps.First().Value;
    Console.WriteLine($"Selected NS: {ip}");
}

async Task<DnsResult> GetDnsResult(IPAddress ipAddress, byte[] packet)
{
    var response = await SendDnsRequest(ipAddress, packet);

    Console.WriteLine("\nReceived DNS Response:");
    foreach (var b in response)
    {
        Console.Write($"{b:X2} ");
    }

// Verify the response ID
    if (response[0] == (byte)(header.Id >> 8) && response[1] == (byte)(header.Id & 0xFF))
    {
        Console.WriteLine("\nResponse ID matches the request ID.");
    }
    else
    {
        Console.WriteLine("\nResponse ID does not match the request ID.");
    }

    var dnsResult = DnsDecoder.DecodeDnsResponse(response);
    return dnsResult;
}

static async Task<byte[]> SendDnsRequest(IPAddress ipAddress, byte[] encodedDnsPacket)
{
    // Create a UDP socket
    using UdpClient udpClient = new UdpClient();
    IPEndPoint endPoint = new IPEndPoint(ipAddress, 53);

    // Send the DNS request
    await udpClient.SendAsync(encodedDnsPacket, encodedDnsPacket.Length, endPoint);

    // Receive the response
    var response = udpClient.Receive(ref endPoint);

    return response;
}