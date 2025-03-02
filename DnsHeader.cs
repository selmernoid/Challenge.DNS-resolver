public class DnsHeader
{
    public ushort Id { get; set; }
    public ushort Flags { get; set; }
    public ushort QdCount { get; set; }
    public ushort AnsCount { get; set; }
    public ushort NSCount { get; set; }
    public ushort AnmCount { get; set; }
    public ushort RClass { get; set; }
    public ushort Rdtype { get; set; }
}