public static class DnsEncoder
{
    public static byte[] EncodeHeader(DnsHeader header, string domain)
    {
        var headerBytes = BitConverter.GetBytes((ushort)header.Id);
        Array.Reverse(headerBytes);

        var flagsBytes = BitConverter.GetBytes((ushort)header.Flags);
        Array.Reverse(flagsBytes);

        var questionCountBytes = BitConverter.GetBytes((ushort)header.QdCount);
        Array.Reverse(questionCountBytes);

        var answerCountBytes = BitConverter.GetBytes((ushort)header.AnsCount);
        Array.Reverse(answerCountBytes);

        var nsCountBytes = BitConverter.GetBytes((ushort)header.NSCount);
        Array.Reverse(nsCountBytes);

        var anmCountBytes = BitConverter.GetBytes((short)header.AnmCount);
        Array.Reverse(anmCountBytes);

        var rdClassBytes = BitConverter.GetBytes((ushort)header.RClass);
        Array.Reverse(rdClassBytes);

        var rdtypeBytes = BitConverter.GetBytes((ushort)header.Rdtype);
        Array.Reverse(rdtypeBytes);

        var domainBytes = EncodeDomainName(domain);

        return
        [
            // ID (2 bytes)
            headerBytes[0], headerBytes[1],

            // Flags (2 bytes)
            flagsBytes[0], flagsBytes[1],

            // Question Count (2 bytes)
            questionCountBytes[0], questionCountBytes[1],

            // Answer Count (2 bytes)
            answerCountBytes[0], answerCountBytes[1],

            // Name Server Count (2 bytes)
            nsCountBytes[0], nsCountBytes[1],

            // Additional Record Count (2 bytes)
            anmCountBytes[0], anmCountBytes[1],

            // Domain Name (variable length)
            ..domainBytes,

            // Record Type (2 bytes)
            rdtypeBytes[0], rdtypeBytes[1],

            // Record Class (2 bytes)
            rdClassBytes[0], rdClassBytes[1]
        ];
    }

    public static byte[] EncodeDomainName(string domain)
    {
        var labels = domain.Split('.');
        var encodedBytes = new List<byte>();

        foreach (var label in labels)
        {
            if (label.Length > 0)
            {
                encodedBytes.Add((byte)label.Length);
                encodedBytes.AddRange(System.Text.Encoding.ASCII.GetBytes(label));
            }
        }

        // Append the root label
        encodedBytes.Add(0);

        return encodedBytes.ToArray();
    }
}