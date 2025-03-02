using System;
using System.Net;
using System.Net.Sockets;


var header = new DnsHeader
{
    Id = 12345,
    Flags = 0x0100, // Standard query
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

var response = await SendDnsRequest(encodedDnsPacket, header);

Console.WriteLine("\nReceived DNS Response:");
foreach (var b in response)
{
    Console.Write($"{b:X2} ");
}

Console.WriteLine();
var idx = 0;
foreach (var b in response)
{
    Console.Write($"{idx++}:{b:X2} ");
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

DnsDecoder.DecodeDnsResponse(response);


static async Task<byte[]> SendDnsRequest(byte[] encodedDnsPacket, DnsHeader header)
{
    // Create a UDP socket
    using UdpClient udpClient = new UdpClient();
    IPEndPoint endPoint = new IPEndPoint(IPAddress.Parse("8.8.8.8"), 53);

    // Send the DNS request
    await udpClient.SendAsync(encodedDnsPacket, encodedDnsPacket.Length, endPoint);

    // Receive the response
    var response = udpClient.Receive(ref endPoint);

    return response;
}