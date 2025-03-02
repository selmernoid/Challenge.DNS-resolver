using System;
using System.Collections.Generic;
using System.Net;
using System.Text;

public class DnsDecoder
{
    public static void DecodeDnsResponse(byte[] response)
    {
        int index = 0;

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
            return;
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
                Console.WriteLine($"Answer: {answerDomain}, Type: {type}, Class: {@class}, TTL: {ttl}, IP Address: {ipAddress}");
            }

            index += dataLength;
        }
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
