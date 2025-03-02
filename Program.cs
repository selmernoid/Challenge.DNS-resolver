using System;

class Program
{
    static void Main(string[] args)
    {
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
        Console.WriteLine("Encoded DNS Packet:");
        foreach (var b in encodedDnsPacket)
        {
            Console.Write($"{b:X2}");
        }
        
        
    }
}
