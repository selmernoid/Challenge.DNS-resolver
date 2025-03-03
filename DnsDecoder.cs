using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

public class DnsDecoder
{
    public static DnsResult DecodeDnsResponse(byte[] response)
    {
        int index = 0;
        var ipAddresses = new List<IPAddress>();
        var nsServers = new List<string>();

        // Parse Header
        var header = new DnsHeader
        {
            Id = (ushort)((response[index++] << 8) | response[index++]),
            Flags = (ushort)((response[index++] << 8) | response[index++]),
            QdCount = (ushort)((response[index++] << 8) | response[index++]),
            AnsCount = (ushort)((response[index++] << 8) | response[index++]),
            NSCount = (ushort)((response[index++] << 8) | response[index++]),
            AnmCount = (ushort)((response[index++] << 8) | response[index++])
        };

        // Check QR bit
        if ((header.Flags & 0x8000) == 0)
        {
            Console.WriteLine("QR bit is not set, this is not a response.");
            throw new InvalidDataException("QR bit is not set, this is not a response.");
        }

        // Parse Question Section
        string domain = DecodeDomainName(response, ref index);
        ushort qtype = (ushort)((response[index++] << 8) | response[index++]);
        ushort qclass = (ushort)((response[index++] << 8) | response[index++]);

        Console.WriteLine($"Question: {domain}, Type: {qtype}, Class: {qclass}");

        // Parse Answer Section
        for (int i = 0; i < header.AnsCount; i++)
        {
            string answerDomain = DecodeDomainName(response, ref index);
            ushort type = (ushort)((response[index++] << 8) | response[index++]);
            ushort @class = (ushort)((response[index++] << 8) | response[index++]);
            uint ttl = (uint)((response[index++] << 24) | (response[index++] << 16) | (response[index++] << 8) | response[index++]);
            ushort dataLength = (ushort)((response[index++] << 8) | response[index++]);

            if (type == 1) // A record
            {
                byte[] ipAddressBytes = new byte[4];
                Array.Copy(response, index, ipAddressBytes, 0, 4);
                IPAddress ipAddress = new IPAddress(ipAddressBytes);
                ipAddresses.Add(ipAddress);
                Console.WriteLine($"Answer: {answerDomain}, Type: {type}, Class: {@class}, TTL: {ttl}, IP Address: {ipAddress}");
            }

            index += dataLength;
        }

        // Parse Authority Section
        for (int i = 0; i < header.NSCount; i++)
        {
            string nsDomain = DecodeDomainName(response, ref index);
            ushort type = (ushort)((response[index++] << 8) | response[index++]);
            ushort @class = (ushort)((response[index++] << 8) | response[index++]);
            uint ttl = (uint)((response[index++] << 24) | (response[index++] << 16) | (response[index++] << 8) | response[index++]);
            ushort dataLength = (ushort)((response[index++] << 8) | response[index++]);

            if (type == 2) // NS record
            {
                string nsName = DecodeDomainName(response, ref index);
                Console.WriteLine($"Authority: {nsDomain}, Type: {type}, Class: {@class}, TTL: {ttl}, Name Server: {nsName}");
                nsServers.Add(nsName);
            }

            //index += dataLength; // this offset was done at DecodeDomainName
        }

        // Parse Additional Section
        var additionalRecords = new Dictionary<string, IPAddress>();
        for (int i = 0; i < header.AnmCount; i++)
        {
            string domainName = DecodeDomainName(response, ref index);
            ushort type = (ushort)((response[index++] << 8) | response[index++]);
            ushort @class = (ushort)((response[index++] << 8) | response[index++]);
            uint ttl = (uint)((response[index++] << 24) | (response[index++] << 16) | (response[index++] << 8) | response[index++]);
            ushort dataLength = (ushort)((response[index++] << 8) | response[index++]);

            if (type == 1) // A record
            {
                byte[] ipAddressBytes = new byte[4];
                Array.Copy(response, index, ipAddressBytes, 0, 4);
                IPAddress ipAddress = new IPAddress(ipAddressBytes);
                Console.WriteLine($"Additional: {domainName}, Type: {type}, Class: {@class}, TTL: {ttl}, IP Address: {ipAddress}");
                additionalRecords[domainName] = ipAddress;
            }

            index += dataLength;
        }

        // Check if we have NS records without corresponding A records
        foreach (var nsServer in nsServers)
        {
            if (!additionalRecords.ContainsKey(nsServer))
            {
                Console.WriteLine($"No IP address found for Name Server: {nsServer}");
            }
        }

        return new(ipAddresses, additionalRecords);
    }

    private static string DecodeDomainName(byte[] response, ref int index)
    {
        List<string> labels = new List<string>();
        while (response[index] != 0)
        {
            if ((response[index] & 0xC0) == 0xC0) // Pointer
            {
                int pointerIndex = ((response[index++] & 0x3F) << 8) | response[index++];
                return DecodeDomainName(response, ref pointerIndex);
            }
            else
            {
                int length = response[index++];
                labels.Add(Encoding.ASCII.GetString(response, index, length));
                index += length;
            }
        }
        index++; // Skip the null terminator
        return string.Join(".", labels);
    }
}
