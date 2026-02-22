namespace DBN.ActiveDirectory
{
    internal class TimedCacheItem
    {
        public string Value { get; set; } = null!;
        public DateTime Expiration { get; set; }
    }
}
